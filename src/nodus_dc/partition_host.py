"""Read-only Linux evidence for the private scoped host provider.

Construction is explicit and unregistered. The protected configuration pins a
qualified runtime and managed allocation boundary; neither this reader nor its
SQLite caller creates cgroups, mounts, images, runtimes or another reservation.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import select
import stat
import time
from pathlib import Path

from . import ephemeral, partition_execution as execution
from .errors import Error
from .model import CleanupProof, digest
from .partition_binding import runtime_identity
from .partitions import fields, sha

MIB = 1024**2


def refused():
    return Error("host_resources_unenforced", "the exact protected host evidence is unavailable", 503)


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise refused()
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(refused()))


def identity(info):
    return {"Device":info.st_dev,"Inode":info.st_ino}


def path(value):
    if not isinstance(value, str) or not value.startswith("/") or not value.isascii() or "\x00" in value or "//" in value or str(Path(value)) != value or ".." in Path(value).parts:
        raise refused()
    return Path(value)


class Evidence:
    """A finite read pass; only identity-checked immutable file hashes may be reused."""

    def __init__(self, immutable_hashes=None):
        self.end = time.monotonic() + 2
        self.hashed = {} if immutable_hashes is None else immutable_hashes

    def check(self):
        if time.monotonic() >= self.end: raise refused()

    def protected(self, name, *, directory=False):
        self.check()
        target = path(str(name))
        for parent in reversed((target.parent, *target.parent.parents)):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise refused()
        info = target.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode): raise refused()
        if directory and not stat.S_ISDIR(info.st_mode): raise refused()
        return info

    def read(self, name, limit=65536, *, kernel=False):
        self.check()
        if not kernel: self.protected(name)
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022: raise refused()
            data = bytearray()
            while len(data) <= limit:
                self.check()
                block = os.read(fd, min(65536,limit+1-len(data)))
                if not block: break
                data.extend(block)
            after = os.fstat(fd)
            if len(data) > limit or identity(before) != identity(after): raise refused()
            if not kernel and (before.st_size != len(data) or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                               != (after.st_size,after.st_mtime_ns,after.st_ctime_ns)): raise refused()
            return bytes(data), identity(before)
        finally: os.close(fd)

    def text(self, name, limit=4096, *, kernel=True):
        return self.read(name,limit,kernel=kernel)[0].decode("ascii").strip()

    def record(self, name, limit=65536):
        raw, _ = self.read(name,limit)
        return decode(raw), hashlib.sha256(raw).hexdigest()

    def file_hash(self, name, maximum=512*MIB, *, proc=False):
        if not proc: self.protected(name)
        self.check()
        fd = os.open(name,os.O_RDONLY | os.O_CLOEXEC | (0 if proc else os.O_NOFOLLOW))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum: raise refused()
            key = (str(name),before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            if key in self.hashed:
                after=os.fstat(fd)
                if key != (str(name),after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise refused()
                return self.hashed[key]
            h = hashlib.sha256(); count = 0
            while count < before.st_size:
                self.check(); block = os.read(fd,min(MIB,before.st_size-count))
                if not block: raise refused()
                count += len(block); h.update(block)
            after = os.fstat(fd)
            if key != (str(name),after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise refused()
            if len(self.hashed) >= 256: self.hashed.clear()
            self.hashed[key] = h.hexdigest()
            return h.hexdigest()
        finally: os.close(fd)

    def names(self, directory, limit=256, *, dirs=False):
        self.protected(directory,directory=True)
        result = []
        with os.scandir(directory) as entries:
            for entry in entries:
                self.check()
                if entry.is_symlink(): raise refused()
                if dirs and not entry.is_dir(follow_symlinks=False): continue
                result.append(entry.name)
                if len(result) > limit: raise refused()
        return set(result)

    def numbers(self, name):
        result = {}
        for line in self.text(name).splitlines():
            key, value = line.split()
            if key in result or not value.isdecimal(): raise refused()
            result[key] = int(value)
        return result

    def controls(self, directory, expected, identities=None):
        actual_id = identity(self.protected(directory,directory=True))
        for key, want in expected.items():
            raw, observed = self.read(Path(directory)/key,4096,kernel=True)
            if raw.decode("ascii").strip() != want or identities and identities.get(key) != observed: raise refused()
        return actual_id

    def empty(self, directory, expected):
        if identity(self.protected(directory,directory=True)) != expected: raise refused()
        if self.numbers(Path(directory)/"cgroup.events").get("populated") != 0: raise refused()
        if self.text(Path(directory)/"memory.current") != "0": raise refused()

    def mounts(self):
        raw = self.text("/proc/self/mountinfo",MIB)
        entries = []
        for line in raw.splitlines():
            self.check()
            left, right = line.split(" - ",1); a,b = left.split(),right.split()
            if len(a)<6 or len(b)<3 or len(entries)>=4096: raise refused()
            # Every managed path is canonical ASCII without mountinfo escapes.
            entries.append({"id":int(a[0]),"device":a[2],"root":a[3],"path":a[4],
                            "type":b[0],"options":set(a[5].split(","))|set(b[2].split(","))})
        return entries


class LinuxPartitionProvider:
    """The existing seven hooks, backed by a pinned, operator-qualified host configuration."""

    def __init__(self, config_path, config_sha256, *, clock=time.time):
        sha(config_sha256)
        self.path, self.sha256, self.clock = str(path(config_path)), config_sha256, clock
        self._immutable_hashes = {}
        self._configuration(Evidence(self._immutable_hashes))

    def _configuration(self, e, *, artifacts=True):
        config, observed = e.record(self.path)
        if observed != self.sha256: raise refused()
        fields(config,"version host_budget namespace snapshotter fifo_dir content_root creator_path creator_sha256 shared_executables runtime_identity runtime_files devices qualification_path")
        if type(config["version"]) is not int or config["version"] != 1: raise refused()
        for key in ("fifo_dir","content_root"):
            path(config[key])
            if artifacts or key == "fifo_dir": e.protected(config[key],directory=True)
        for key in ("namespace","snapshotter"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}",config[key]): raise refused()
        sha(config["creator_sha256"])
        if artifacts and e.file_hash(config["creator_path"]) != config["creator_sha256"]: raise refused()
        if not isinstance(config["shared_executables"],list) or not 1 <= len(config["shared_executables"]) <= 16: raise refused()
        for item in config["shared_executables"]:
            fields(item,"path sha256"); sha(item["sha256"])
            if artifacts and e.file_hash(item["path"]) != item["sha256"]: raise refused()
        runtime_identity(config["runtime_identity"],config["runtime_identity"]["manifest_sha256"])
        required = {"runsc_sha256","sentry_sha256","scoped_shim_sha256","containerd_shim_sha256","cdi_sha256"}
        if (set(config["runtime_files"]) != required
                or config["runtime_files"]["cdi_sha256"] != config["runtime_identity"]["cdi_path"]): raise refused()
        for key, name in config["runtime_files"].items():
            if artifacts and e.file_hash(name) != config["runtime_identity"][key]: raise refused()
        qualification, qhash = e.record(config["qualification_path"])
        fields(qualification,"version retirement_contract runtime_identity creator_sha256 devices artifacts")
        if (type(qualification["version"]) is not int or qualification["version"] != 1 or qualification["retirement_contract"] != "scoped-host-positive-retirement.v1"
                or qhash != config["runtime_identity"]["qualification_sha256"]
                or qualification["creator_sha256"] != config["creator_sha256"]
                or qualification["devices"] != config["devices"]
                or qualification["runtime_identity"] != {k:v for k,v in config["runtime_identity"].items() if k != "qualification_sha256"}):
            raise refused()
        if not isinstance(config["devices"],list) or not 1 <= len(config["devices"]) <= 64: raise refused()
        for item in config["devices"]:
            fields(item,"device accelerator")
            if not isinstance(item["device"],dict) or not isinstance(item["accelerator"],str) or not item["accelerator"]: raise refused()
        if not isinstance(qualification["artifacts"],list) or len(qualification["artifacts"])>128: raise refused()
        pinned={}
        for item in qualification["artifacts"]:
            fields(item,"path sha256"); path(item["path"]); sha(item["sha256"])
            if item["path"] in pinned: raise refused()
            pinned[item["path"]]=item["sha256"]
            if artifacts and e.file_hash(item["path"])!=item["sha256"]: raise refused()
        if artifacts:
            cdi,_=e.record(config["runtime_files"]["cdi_sha256"],MIB)
            edits=[cdi.get("containerEdits",{})]+[d.get("containerEdits",{}) for d in cdi.get("devices",[])]
            if len(edits)>65: raise refused()
            paths=set()
            for edit in edits:
                mounts,hooks=edit.get("mounts",[]),edit.get("hooks",[])
                if len(mounts)>64 or len(hooks)>16: raise refused()
                paths.update(m["hostPath"] for m in mounts)
                paths.update(h["path"] for h in hooks)
            if paths!=set(pinned): raise refused()
        return config

    def _envelope(self, e, c):
        b = c["host_budget"]
        # Reuse the wire validator against this exact allocation identity.
        execution.host_budget(b,{"offer":{"partition":{"boot_id":b["boot_id"],"authority_incarnation":b["authority_incarnation"]}}})
        if e.text("/proc/sys/kernel/random/boot_id",64) != b["boot_id"]: raise refused()
        for name in ("pid","user","cgroup"):
            if os.readlink("/proc/self/ns/"+name) != b[name+"_namespace"]: raise refused()
        root, shared = path(b["root"]["path"]),path(b["shared"]["path"])
        if shared.parent != root: raise refused()
        mounts = e.mounts()
        if not any(m["path"] == "/sys/fs/cgroup" and m["type"] == "cgroup2" for m in mounts): raise refused()
        for item in (b["root"],b["shared"]):
            expected = {"cgroup.type":"domain","cpu.max":f'{item["cpu_millis"]*100} 100000',"cpu.max.burst":"0",
                        "memory.max":str(item["memory_bytes"]),"memory.swap.max":"0","pids.max":str(item["pids"])}
            if e.controls(item["path"],expected) != {"Device":item["device"],"Inode":item["inode"]}: raise refused()
        if e.text(root/"cgroup.procs") or not {"cpu","memory","pids"} <= set(e.text(root/"cgroup.subtree_control").split()): raise refused()
        if e.names(root,dirs=True) - {shared.name,"nodus-scoped-owners","nodus-scoped-host"}: raise refused()
        for parent in (root/"nodus-scoped-owners",root/"nodus-scoped-host"):
            if parent.exists() and (e.text(parent/"cgroup.procs") or not {"cpu","memory","pids"} <= set(e.text(parent/"cgroup.subtree_control").split())): raise refused()
        allowed = {v["sha256"] for v in c["shared_executables"]} | {c["creator_sha256"]}
        queue = [shared]; count=0; own=False
        while queue:
            directory=queue.pop(); count+=1
            if count>128: raise refused()
            queue.extend(directory/name for name in e.names(directory,128,dirs=True))
            members=e.text(directory/"cgroup.procs",16384).split()
            if len(members)>b["shared"]["pids"]: raise refused()
            for member in members:
                pid=int(member)
                if e.file_hash(f"/proc/{pid}/exe",proc=True) not in allowed: raise refused()
                own = own or pid == os.getpid()
        if not own: raise refused()  # The authority itself is part of the finite shared allocation.
        return b

    def _image(self,e,c,image,lease):
        execution.qualified_image(image,lease)
        if image["namespace"]!=c["namespace"] or image["snapshotter"]!=c["snapshotter"]: raise refused()
        root=path(c["content_root"])/"blobs"/"sha256"
        manifest,mhash=e.record(root/image["manifest_sha256"],MIB)
        if mhash!=image["manifest_sha256"] or manifest.get("schemaVersion")!=2 or manifest.get("mediaType") not in {
                "application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"}: raise refused()
        config=manifest.get("config",{})
        if config.get("digest")!="sha256:"+image["config_sha256"] or config.get("urls"): raise refused()
        layers=manifest.get("layers")
        if not isinstance(layers,list) or not 1<=len(layers)<=128: raise refused()
        allowed={"application/vnd.oci.image.layer.v1.tar","application/vnd.oci.image.layer.v1.tar+gzip","application/vnd.oci.image.layer.v1.tar+zstd","application/vnd.docker.image.rootfs.diff.tar.gzip"}
        for layer in layers:
            if layer.get("mediaType") not in allowed or layer.get("urls") or not re.fullmatch(r"sha256:[0-9a-f]{64}",layer.get("digest","")): raise refused()
        body,chash=e.record(root/image["config_sha256"],MIB)
        if chash!=image["config_sha256"] or body.get("os")!="linux" or body.get("architecture")!="amd64": raise refused()
        process=body.get("config") or {}
        if process.get("User","")!=image["user"]: raise refused()
        rootfs=body.get("rootfs",{})
        diffs=rootfs.get("diff_ids")
        if rootfs.get("type")!="layers" or not isinstance(diffs,list) or len(diffs)!=len(layers): raise refused()
        chain=""
        for item in diffs:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}",item): raise refused()
            chain=item if not chain else "sha256:"+hashlib.sha256((chain+" "+item).encode()).hexdigest()
        if chain!="sha256:"+image["rootfs_chain_sha256"]: raise refused()
        # Current namespace/unpack state is independently repeated by the Go pre-Claim and runtime cache readers.

    @staticmethod
    def _paths(c,ref):
        ns=c["namespace"]; attempt=ref["attempt_id"]
        key=hashlib.sha256(f'{len(ns)}:{ns}/{len(attempt)}:{attempt}/{ref["epoch"]}'.encode()).hexdigest()
        root=path(c["host_budget"]["root"]["path"])
        owner=root/"nodus-scoped-owners"/key
        return key,path(c["fifo_dir"])/"guardians"/key,owner,owner/"nodus-epochs"/key,owner/"nodus-guardians"/key,root/"nodus-scoped-host"/key

    @staticmethod
    def _grant_digest(binding):
        p=binding["lease"]["offer"]["partition"]; d=binding["device_observation"]; r=binding["runtime_identity"]
        # Go MIGDeviceGrant field order is part of the runtime's raw JSON digest.
        grant={"ResourceID":p["resource_id"],"AuthorityIncarnation":p["authority_incarnation"],
               "ConfigurationGeneration":p["configuration_generation"],"BootID":p["boot_id"],
               "ParentUUID":p["parent_uuid"],"PCIBusID":d["pci_bus_id"],"MIGUUID":p["mig_uuid"],
               "GPUInstance":p["gpu_instance"],"ComputeInstance":p["compute_instance"],
               "DriverVersion":d["driver_version"],"ModuleSourceVersion":d["driver_source_version"],
               "BindingSHA256":p["binding_sha256"],"QualificationSHA256":r["qualification_sha256"],
               "RunscSHA256":r["runsc_sha256"],"CDIPath":r["cdi_path"],"CDISHA256":r["cdi_sha256"]}
        if len(d["devices"])!=5: raise refused()
        for role,node in zip(("Frontend","Control","UVM","GI","CI"),d["devices"]):
            if node["type"]!="c": raise refused()
            grant[role]={"Path":node["path"],"Major":node["major"],"Minor":node["minor"]}
        raw=json.dumps(grant,separators=(",",":"),ensure_ascii=False).replace("&","\\u0026").replace("<","\\u003c").replace(">","\\u003e")
        return hashlib.sha256(raw.encode()).hexdigest()

    def _daemon(self,e,c,value):
        fields(value,"Address BootID ExecutableSHA256 PID StartTicks UID GID PIDNamespace UserNamespace MountNamespace CgroupNamespace Root State Socket Executable RootIdentity StateIdentity Store StoreFD")
        for key in ("PID","StartTicks","StoreFD"):
            if type(value[key]) is not int or not 0 <= value[key] < 2**63: raise refused()
        if not 0 < value["PID"] < 2**31 or not value["StartTicks"] or value["StoreFD"] > 1048576: raise refused()
        if type(value["UID"]) is not int or type(value["GID"]) is not int or value["UID"] != 0 or value["GID"] != 0: raise refused()
        if value["BootID"] != c["host_budget"]["boot_id"] or e.text("/proc/sys/kernel/random/boot_id",64) != value["BootID"]: raise refused()
        if value["ExecutableSHA256"] not in {v["sha256"] for v in c["shared_executables"]}: raise refused()
        root,state,address = (path(value[k]) for k in ("Root","State","Address"))
        if path(c["content_root"]) != root/"io.containerd.content.v1.content": raise refused()
        for key in ("Socket","Executable","RootIdentity","StateIdentity","Store"):
            fields(value[key],"Device Inode")
            if any(type(v) is not int or not 0 < v < 2**64 for v in value[key].values()): raise refused()
        pid=value["PID"]; process=Path(f"/proc/{pid}")
        pidfd=os.pidfd_open(pid,0)
        try:
            poll=select.poll();poll.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
            # The protected receipt supplies original SO_PEERCRED/CLI provenance.
            # Recheck the original live kernel identities; never query daemon metadata here.
            for _ in range(2):
                e.check()
                if poll.poll(0): raise refused()
                raw=e.text(process/"stat",4096);tail=raw[raw.rindex(")")+2:].split()
                if tail[0]=="Z" or int(tail[19])!=value["StartTicks"]: raise refused()
                status=dict(line.split(":",1) for line in e.text(process/"status",16384).splitlines() if ":" in line)
                if any([int(v) for v in status[k].split()] != [0]*4 for k in ("Uid","Gid")): raise refused()
                for key,name in (("PIDNamespace","pid"),("UserNamespace","user"),("MountNamespace","mnt"),("CgroupNamespace","cgroup")):
                    if os.readlink(process/"ns"/name)!=value[key] or os.readlink(Path("/proc/self/ns")/name)!=value[key]: raise refused()
                shared=c["host_budget"]["shared"]["path"].removeprefix("/sys/fs/cgroup")
                current=e.text(process/"cgroup")
                if current!="0::"+shared and not current.startswith("0::"+shared+"/"): raise refused()
                for directory,key in ((root,"RootIdentity"),(state,"StateIdentity")):
                    info=e.protected(directory,directory=True)
                    if info.st_gid!=0 or identity(info)!=value[key]: raise refused()
                e.protected(address.parent,directory=True);sock=address.lstat()
                if (not stat.S_ISSOCK(sock.st_mode) or sock.st_uid!=0 or sock.st_gid!=0 or sock.st_mode&0o002
                        or identity(sock)!=value["Socket"]): raise refused()
                executable=os.stat(process/"exe")
                if (executable.st_uid!=0 or executable.st_gid!=0 or executable.st_mode&0o022
                        or identity(executable)!=value["Executable"] or e.file_hash(process/"exe",256*MIB,proc=True)!=value["ExecutableSHA256"]): raise refused()
                store_path=root/"io.containerd.metadata.v1.bolt"/"meta.db"
                store=e.protected(store_path)
                opened=os.stat(process/"fd"/str(value["StoreFD"]))
                if (store.st_gid!=0 or not stat.S_ISREG(store.st_mode) or not stat.S_ISREG(opened.st_mode)
                        or os.readlink(process/"fd"/str(value["StoreFD"]))!=str(store_path)
                        or identity(store)!=value["Store"] or identity(opened)!=value["Store"]): raise refused()
            if poll.poll(0): raise refused()
        finally: os.close(pidfd)

    def _records(self,e,c,state):
        binding=state["binding"]; lease=binding["lease"]; ch=lease["ephemeral"]["charge"]
        key,directory,owner,epoch,guardian,host=self._paths(c,binding["ref"])
        if e.protected(directory,directory=True).st_mode & 0o077: raise refused()
        guard,_=e.record(directory/"intent.json",16384)
        fields(guard,"Version Executor Ref Namespace BootID TimeNamespace HostScope CgroupPath Freeze Kill ScopeSHA256 HostSHA256")
        if (guard["Version"]!=5 or guard["Executor"]!=2 or guard["Namespace"]!=c["namespace"]
                or type(guard["Ref"].get("Epoch")) is not int or guard["Ref"]!={"AttemptID":binding["ref"]["attempt_id"],"Epoch":binding["ref"]["epoch"]}
                or guard["BootID"]!=binding["host_budget"]["boot_id"] or guard["CgroupPath"]!=str(epoch)):
            raise refused()
        hostscope=guard["HostScope"]; b=binding["host_budget"]
        if e.text("/proc/sys/kernel/random/boot_id",64)!=b["boot_id"]: raise refused()
        for name in ("pid","user","cgroup"):
            if os.readlink("/proc/self/ns/"+name)!=b[name+"_namespace"]: raise refused()
        if hostscope!={"BootID":b["boot_id"],"CgroupNamespace":b["cgroup_namespace"],"UserNamespace":b["user_namespace"],
                "PIDNamespace":b["pid_namespace"],"AllocationRoot":b["root"]["path"],"AllocationDevice":b["root"]["device"],"AllocationInode":b["root"]["inode"]}: raise refused()
        if os.readlink("/proc/self/ns/time")!=guard["TimeNamespace"]: raise refused()
        limits,lhash=e.record(directory/"scoped-limits.json",16384)
        fields(limits,"Version Root Plan Owner Epoch Guardian Controls")
        if type(limits["Version"]) is not int or limits["Version"]!=1 or limits["Root"]!=str(owner.parent.parent) or lhash!=guard["ScopeSHA256"]: raise refused()
        expected={"Version":1,"BindingSHA256":state["binding_sha256"],"HostBudgetSHA256":digest(b),
                  "Task":{"CPUMillis":lease["resources"]["cpu_millis"],"MemoryBytes":lease["resources"]["memory_bytes"],"PIDs":512},
                  "HostScratchBytes":ch["host_memory_bytes"],"OwnerOverheadBytes":ch["owner_overhead_bytes"],"OwnerOverheadCPUMillis":ch["owner_cpu_millis"]}
        if limits["Plan"]!=expected: raise refused()
        scope,shash=e.record(directory/"host-scope.json",32768)
        fields(scope,"Version Guard Plan Root GroupPath GuardianPath Group Freeze Kill CreatorLock Controls Visible Stage Internal")
        metadata,_=e.record(directory/"metadata-intent.json",16384)
        container=binding["ref"]["attempt_id"]+"-e"+str(binding["ref"]["epoch"])
        fields(metadata,"Version Guard Snapshotter ContainerID SnapshotKey Daemon")
        if (type(metadata["Version"]) is not int or metadata["Version"]!=2 or metadata["Guard"]!=guard
                or metadata["Snapshotter"]!=binding["image"]["snapshotter"] or metadata["ContainerID"]!=container
                or metadata["SnapshotKey"]!=container): raise refused()
        self._daemon(e,c,metadata["Daemon"])
        original={**guard,"Version":4}; original.pop("HostSHA256")
        if scope["Version"]!=2 or scope["Guard"]!=original or shash!=guard["HostSHA256"] or scope["Root"]!=limits["Root"] or scope["GroupPath"]!=str(host) or scope["GuardianPath"]!=str(guardian): raise refused()
        plan=scope["Plan"]; fields(plan,"Version SpecSHA256 DeviceSHA256 VisibleBytes StageBytes")
        if plan["Version"]!=2 or plan["SpecSHA256"]!=lease["ephemeral"]["spec_sha256"] or plan["VisibleBytes"]!=lease["resources"]["scratch_bytes"] or plan["StageBytes"]!=ch["stage_bytes"]: raise refused()
        if plan["DeviceSHA256"] != self._grant_digest(binding): raise refused()
        for title,name,size,inodes in (("Visible","visible",plan["VisibleBytes"],256),("Stage","stage",plan["StageBytes"],256),("Internal","internal",8192,8)):
            m=scope[title]; fields(m,"Path Bytes Inodes MountID Device Identity")
            if m["Path"]!=str(directory/"host"/name) or m["Bytes"]!=size or m["Inodes"]!=inodes: raise refused()
        for name,want in ((owner,limits["Owner"]),(epoch,limits["Epoch"]),(guardian,limits["Guardian"]),(host,scope["Group"])):
            if identity(e.protected(name,directory=True))!=want: raise refused()
        if identity(e.protected(directory/"bootstrap.lock"))!=scope["CreatorLock"]: raise refused()
        for group, freeze, kill in ((epoch,guard["Freeze"],guard["Kill"]),(host,scope["Freeze"],scope["Kill"])):
            if identity(e.protected(group/"cgroup.freeze"))!=freeze or identity(e.protected(group/"cgroup.kill"))!=kill: raise refused()
        return directory,owner,epoch,guardian,host,guard,limits,scope,shash

    def _owner(self,e,c,state,*,clean=False,scope_hash=None):
        directory,owner,epoch,guardian,host,guard,limits,scope,actual=self._records(e,c,state)
        if scope_hash is not None and actual!=scope_hash: raise refused()
        if state["host_scope_sha256"] and actual!=state["host_scope_sha256"]: raise refused()
        mounts=e.mounts()
        if clean:
            for filename,want in (("removed.json",guard),("revoked.json",guard),("owner-empty.json",guard),
                                  ("host-retired.json",scope),("retired.json",{"Guard":guard,"Group":limits["Guardian"]}),
                                  ("guardian.json",{"Guard":guard,"Group":limits["Guardian"]})):
                if e.record(directory/filename)[0]!=want: raise refused()
            lock=os.open(directory/"bootstrap.lock",os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                for group,want in ((owner,limits["Owner"]),(epoch,limits["Epoch"]),(guardian,limits["Guardian"]),(host,scope["Group"])):
                    e.empty(group,want)
                for title in ("Visible","Stage","Internal"):
                    m=scope[title]
                    if e.record(directory/("host-unmount-"+Path(m["Path"]).name+".json"))[0]!=m: raise refused()
                    if any(v["path"]==m["Path"] or v["path"].startswith(m["Path"]+"/") for v in mounts): raise refused()
            finally: os.close(lock)
            return actual
        for filename in ("revoked.json","expired.json","retired.json","removed.json"):
            if os.path.lexists(directory/filename): raise refused()
        task=limits["Plan"]["Task"]; plan=limits["Plan"]
        expected={"cgroup.type":"domain","memory.max":str(task["MemoryBytes"]+plan["OwnerOverheadBytes"]),
                  "memory.swap.max":"0","memory.oom.group":"1","pids.max":"512","cpu.max.burst":"0",
                  "cpu.max":f'{(task["CPUMillis"]+plan["OwnerOverheadCPUMillis"])*100} 100000'}
        if set(limits["Controls"]) != set(expected)|{"memory.events.local"} or set(scope["Controls"]) != set(expected)|{"memory.events.local"}: raise refused()
        e.controls(owner,expected,limits["Controls"])
        e.controls(host,{**expected,"memory.max":str(plan["HostScratchBytes"]),"pids.max":"64","cpu.max":"25000 100000"},scope["Controls"])
        for group, controls in ((owner,limits["Controls"]),(host,scope["Controls"])):
            if identity(e.protected(group/"memory.events.local"))!=controls["memory.events.local"]: raise refused()
            events=e.numbers(group/"memory.events.local")
            if any(events.get(key)!=0 for key in ("oom","oom_kill","oom_group_kill")): raise refused()
        queue=[owner]; count=0; processes=0
        while queue:
            group=queue.pop(); count+=1
            if count>1024: raise refused()
            queue.extend(group/name for name in e.names(group,1024,dirs=True))
            for member in e.text(group/"cgroup.procs",16384).split():
                processes+=1
                if processes>512 or e.text(f"/proc/{int(member)}/oom_score_adj")=="-1000": raise refused()
        for group in (epoch.parent,epoch,guardian.parent,guardian):
            if e.text(group/"memory.max")!="max": raise refused()
        if e.text(host/"cgroup.freeze")!="0": raise refused()
        members=e.text(guardian/"cgroup.procs").split()
        if len(members)!=1: raise refused()
        pid=int(members[0]); pidfd=os.pidfd_open(pid,0)
        try:
            poll=select.poll();poll.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
            if poll.poll(0) or e.file_hash(f"/proc/{pid}/exe",proc=True)!=c["creator_sha256"]: raise refused()
            if "__nodus_container_guardian" not in e.text(f"/proc/{pid}/cmdline",4096).split("\0"): raise refused()
            if e.text(f"/proc/{pid}/oom_score_adj")=="-1000" or poll.poll(0): raise refused()
        finally: os.close(pidfd)
        for title in ("Visible","Stage","Internal"):
            m=scope[title]; selected=[v for v in mounts if v["path"]==m["Path"]]
            if len(selected)!=1 or any(v["path"].startswith(m["Path"]+"/") for v in mounts): raise refused()
            v=selected[0]; options={"nodev","nosuid","noswap",f'nr_inodes={m["Inodes"]}',f'size={m["Bytes"]//1024}k'}
            info=os.statvfs(m["Path"])
            if (v["id"]!=m["MountID"] or v["device"]!=m["Device"] or v["type"]!="tmpfs" or v["root"]!="/" or not options<=v["options"]
                    or identity(e.protected(m["Path"],directory=True))!=m["Identity"] or info.f_blocks*info.f_frsize!=m["Bytes"] or info.f_files!=m["Inodes"]): raise refused()
        return actual

    def _reservation(self,e,c,local,row,context):
        lease=context["lease"]; proof=decode(row["enforcement"])
        execution.qualified_proof(proof,lease)
        if (proof.get("provider_config_sha256")!=self.sha256 or proof["host_budget"]!=c["host_budget"]
                or local["id"]!=row["lease_id"] or any(row[k]!=lease["ephemeral"]["charge"]["aggregate"][k] for k in lease["resources"])): raise refused()
        self._image(e,c,proof["qualified_image"],lease)
        state=context["binding_state"]
        if state is None: return
        key,directory,owner,epoch,guardian,host=self._paths(c,state["binding"]["ref"])
        if state["phase"] in {"committed","creation-issued"}:
            if any(os.path.lexists(p) for p in (directory,owner,host)): raise refused()
        elif state["phase"]=="creation-consumed":
            if any(os.path.lexists(p) for p in (directory,owner,host)):
                self._owner(e,c,state)
        elif state["phase"]=="host-published": self._owner(e,c,state)
        elif state["phase"]!="retired": raise refused()

    def qualification(self,binding):
        e=Evidence(self._immutable_hashes); c=self._configuration(e); self._envelope(e,c)
        match=[v for v in c["devices"] if v.get("device")==binding]
        if len(match)!=1: raise refused()
        return {"qualified":True,"continuous_configuration_authority":True,"runtime_sha256":c["runtime_identity"]["manifest_sha256"],
                "accelerator":match[0]["accelerator"],"execution_identity":copy.deepcopy(c["runtime_identity"])}

    def host_capacity(self,*,accounting_version=None):
        if accounting_version!=ephemeral.ACCOUNTING: raise refused()
        e=Evidence(self._immutable_hashes);c=self._configuration(e);b=self._envelope(e,c)
        return {"accounting_version":ephemeral.ACCOUNTING,"capacity":copy.deepcopy(b["capacity"])}

    def prepare_reservation(self,local,resources,*,context):
        e=Evidence(self._immutable_hashes);c=self._configuration(e);b=self._envelope(e,c);lease=context["lease"]
        execution.host_budget(b,lease); self._image(e,c,context["qualified_image"],lease)
        if resources!=lease["ephemeral"]["charge"]["aggregate"] or context["authority_scope"]!={"authority_incarnation":b["authority_incarnation"],"accounting_version":ephemeral.ACCOUNTING}: raise refused()
        return {"contract":execution.PROVIDER,"accounting_version":ephemeral.ACCOUNTING,"enforcement_ready":True,
                "provider_config_sha256":self.sha256,"qualified_image":copy.deepcopy(context["qualified_image"]),"host_budget":copy.deepcopy(b)}

    def verify_reservation(self,local,row,*,context):
        e=Evidence(self._immutable_hashes);c=self._configuration(e);self._envelope(e,c);self._reservation(e,c,local,row,context)
        return True

    def check_execution(self,local,lease,*,context):
        e=Evidence(self._immutable_hashes);c=self._configuration(e);self._envelope(e,c)
        state=context["binding_state"];purpose=context["purpose"]
        if context.get("creator") is not None:
            who=context["creator"]
            if who["executable_sha256"]!=c["creator_sha256"] or who["uid"]!=0 or who["gid"]!=0: raise refused()
            shared=c["host_budget"]["shared"]["path"].removeprefix("/sys/fs/cgroup")
            actual=e.text(f'/proc/{who["pid"]}/cgroup')
            if actual!="0::"+shared and not actual.startswith("0::"+shared+"/"): raise refused()
        if purpose=="publish": self._owner(e,c,state,scope_hash=context["host_scope_sha256"])
        elif state and state["phase"]=="host-published": self._owner(e,c,state)
        return True

    def verify_host_accounting(self,capacity,held,scope):
        e=Evidence(self._immutable_hashes);c=self._configuration(e);b=self._envelope(e,c)
        if capacity!=b["capacity"] or scope.get("accounting_version")!=ephemeral.ACCOUNTING or scope["authority_incarnation"]!=b["authority_incarnation"] or len(held)>b["max_claims"]: raise refused()
        expected=set(); retired=scope.get("retired",[])
        if not isinstance(retired,list) or len(retired)>256: raise refused()
        for item in [*held,*retired]:
            row=item.get("provider_row");state=item.get("binding_state")
            if row is None: raise refused()
            if state is None: continue
            key,directory,owner,epoch,guardian,host=self._paths(c,state["binding"]["ref"])
            if key in expected: raise refused()
            if item in retired:
                if state["phase"]!="retired": raise refused()
                if state["phase_revision"]<=3:
                    if any(os.path.lexists(p) for p in (directory,owner,host)): raise refused()
                else: self._owner(e,c,state,clean=True)
            if any(os.path.lexists(p) for p in (directory,owner,host)): expected.add(key)
        root=path(b["root"]["path"])
        for directory in (root/"nodus-scoped-owners",root/"nodus-scoped-host",path(c["fifo_dir"])/"guardians"):
            names=e.names(directory,320,dirs=directory != path(c["fifo_dir"])/"guardians") if directory.exists() else set()
            if names!=expected: raise refused()
        return True

    def verify_clean(self,local,lease,*,context):
        e=Evidence(self._immutable_hashes);c=self._configuration(e,artifacts=False)
        proof=decode(context["provider_row"]["enforcement"]);execution.qualified_proof(proof,lease)
        if proof.get("provider_config_sha256")!=self.sha256: raise refused()
        state=context["binding_state"]
        clean=state is None  # No Bind/Begin exists in this exact authority row.
        if state is not None and state["phase"]=="retired":
            predecessor=state["phase_revision"]-1
            key,directory,owner,epoch,guardian,host=self._paths(c,state["binding"]["ref"])
            if predecessor<=2:
                clean=not any(os.path.lexists(p) for p in (directory,owner,host))
            else:
                self._owner(e,c,state,clean=True);clean=True
        return CleanupProof(clean,self.clock(),local["id"],local["generation"],tuple(local["resources"]),
                            {"provider_config_sha256":self.sha256,"kernel_retirement_verified":clean})
