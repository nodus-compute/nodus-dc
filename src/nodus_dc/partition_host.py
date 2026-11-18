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
ORIGINAL_HIGH_FILES = ("original-high-intent.json", "original-high-outcome.json",
                       "original-high-intent.json.tmp", "original-high-outcome.json.tmp")


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
        if (type(qualification["version"]) is not int or qualification["version"] != 1 or qualification["retirement_contract"] != "scoped-host-workload-retirement.v4"
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

    def _record_pair(self,e,c,state,*,retired=False):
        binding=state["binding"]; lease=binding["lease"]; ch=lease["ephemeral"]["charge"]
        key,directory,owner,epoch,guardian,host=self._paths(c,binding["ref"])
        if any(os.path.lexists(directory/name) for name in ("creation-retired.json",*ORIGINAL_HIGH_FILES,
                "host-retired.json","host-high-intent.json","host-high-outcome.json")): raise refused()
        if e.protected(directory,directory=True).st_mode & 0o077: raise refused()
        scope,shash,_=self._creation_record(e,directory,"host-scope.json",32768)
        fields(scope,"Version Guard Plan Root GroupPath GuardianPath Group Freeze Kill CreatorLock Controls CreationIntentSHA256 WorkerPath Worker WorkerControls Visible Stage Internal EpochParent GuardianParent")
        original=scope["Guard"]
        fields(original,"Version Executor Ref Namespace BootID TimeNamespace HostScope CgroupPath Freeze Kill ScopeSHA256")
        if type(original["Version"]) is not int or original["Version"]!=4: raise refused()
        guard={**original,"Version":5,"HostSHA256":shash}
        if (guard["Executor"]!=2 or guard["Namespace"]!=c["namespace"]
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
        limits,lhash,_=self._creation_record(e,directory,"scoped-limits.json",16384)
        fields(limits,"Version Root Plan Owner Epoch Guardian Controls")
        if type(limits["Version"]) is not int or limits["Version"]!=1 or limits["Root"]!=str(owner.parent.parent) or lhash!=guard["ScopeSHA256"]: raise refused()
        expected={"Version":1,"BindingSHA256":state["binding_sha256"],"HostBudgetSHA256":digest(b),
                  "Task":{"CPUMillis":lease["resources"]["cpu_millis"],"MemoryBytes":lease["resources"]["memory_bytes"],"PIDs":512},
                  "HostScratchBytes":ch["host_memory_bytes"],"OwnerOverheadBytes":ch["owner_overhead_bytes"],"OwnerOverheadCPUMillis":ch["owner_cpu_millis"]}
        if limits["Plan"]!=expected: raise refused()
        if type(scope["Version"]) is not int or scope["Version"]!=4 or scope["Root"]!=limits["Root"] or scope["GroupPath"]!=str(host) or scope["GuardianPath"]!=str(guardian): raise refused()
        plan=scope["Plan"]; fields(plan,"Version SpecSHA256 DeviceSHA256 VisibleBytes StageBytes")
        if plan["Version"]!=2 or plan["SpecSHA256"]!=lease["ephemeral"]["spec_sha256"] or plan["VisibleBytes"]!=lease["resources"]["scratch_bytes"] or plan["StageBytes"]!=ch["stage_bytes"]: raise refused()
        if plan["DeviceSHA256"] != self._grant_digest(binding): raise refused()
        mount_seen=[set(),set(),set()]
        for title,name,size,inodes in (("Visible","visible",plan["VisibleBytes"],256),("Stage","stage",plan["StageBytes"],256),("Internal","internal",8192,8)):
            for seen,value in zip(mount_seen,self._mount(scope[title],str(directory/"host"/name),size,inodes)):
                if value in seen: raise refused()
                seen.add(value)
        if not retired:
            for name,want in ((owner,limits["Owner"]),(epoch.parent,scope["EpochParent"]),(epoch,limits["Epoch"]),
                    (guardian.parent,scope["GuardianParent"]),(guardian,limits["Guardian"]),(host,scope["Group"])):
                if identity(e.protected(name,directory=True))!=want: raise refused()
        if identity(e.protected(directory/"bootstrap.lock"))!=scope["CreatorLock"]: raise refused()
        intent,ihash,_=self._creation_intent(e,c,state)
        if (intent["Limits"]!=limits["Plan"] or intent["Plan"]!=scope["Plan"]
                or ihash!=scope["CreationIntentSHA256"] or scope["WorkerPath"]!=str(host/"worker")): raise refused()
        self._host_identities(scope,b["root"]["device"])
        fields(limits["Controls"],"cgroup.type memory.max memory.swap.max memory.oom.group pids.max cpu.max.burst cpu.max memory.events.local")
        seen={b["root"]["inode"],b["shared"]["inode"]}
        for item in (limits["Owner"],limits["Epoch"],limits["Guardian"],scope["EpochParent"],scope["GuardianParent"],
                     scope["Group"],scope["Worker"],guard["Freeze"],guard["Kill"],scope["Freeze"],scope["Kill"],
                     *limits["Controls"].values(),*scope["Controls"].values(),*scope["WorkerControls"].values()):
            fields(item,"Device Inode")
            if any(type(v) is not int or not 0<v<2**64 for v in item.values()) or item["Device"]!=b["root"]["device"] or item["Inode"] in seen: raise refused()
            seen.add(item["Inode"])
        if not retired:
            for group, freeze, kill in ((epoch,guard["Freeze"],guard["Kill"]),(host,scope["Freeze"],scope["Kill"])):
                if identity(e.protected(group/"cgroup.freeze"))!=freeze or identity(e.protected(group/"cgroup.kill"))!=kill: raise refused()
        return directory,owner,epoch,guardian,host,guard,limits,scope,shash

    @staticmethod
    def _mount(m,name,size,inodes):
        """Strict historical mount codec, shared by full-scope and original-abort reads."""
        fields(m,"Path Bytes Inodes MountID Device Identity");fields(m["Identity"],"Device Inode")
        if any(type(v) is not int or not 0<v<2**64 for v in m["Identity"].values()): raise refused()
        if type(m["MountID"]) is not int or not 0<m["MountID"]<=2**31-1: raise refused()
        if (m["Path"]!=name or type(m["Bytes"]) is not int or m["Bytes"]!=size
                or type(m["Inodes"]) is not int or m["Inodes"]!=inodes): raise refused()
        if not isinstance(m["Device"],str) or not re.fullmatch(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)",m["Device"]): raise refused()
        if any(int(v)>2**32-1 for v in m["Device"].split(":")): raise refused()
        if m["Device"]!=f'{os.major(m["Identity"]["Device"])}:{os.minor(m["Identity"]["Device"])}': raise refused()
        return m["MountID"],m["Device"],(m["Identity"]["Device"],m["Identity"]["Inode"])

    def _metadata(self,e,c,state,directory,guard):
        binding=state["binding"]
        metadata,_=e.record(directory/"metadata-intent.json",16384)
        container=binding["ref"]["attempt_id"]+"-e"+str(binding["ref"]["epoch"])
        fields(metadata,"Version Guard Snapshotter ContainerID SnapshotKey Daemon")
        if (type(metadata["Version"]) is not int or metadata["Version"]!=2 or metadata["Guard"]!=guard
                or metadata["Snapshotter"]!=binding["image"]["snapshotter"] or metadata["ContainerID"]!=container
                or metadata["SnapshotKey"]!=container): raise refused()
        self._daemon(e,c,metadata["Daemon"])

    def _records(self,e,c,state):
        records=self._record_pair(e,c,state)
        directory,_,_,_,_,guard,_,_,_=records
        if e.record(directory/"intent.json",16384)[0]!=guard: raise refused()
        self._metadata(e,c,state,directory,guard)
        return records

    @staticmethod
    def _host_identities(scope,device):
        base={"cgroup.type","memory.max","memory.swap.max","memory.oom.group","pids.max","cpu.max.burst","cpu.max",
              "memory.events.local","memory.high","cgroup.subtree_control"}
        fields(scope["Controls"]," ".join(base));fields(scope["WorkerControls"]," ".join(base|{"cgroup.freeze"}))
        seen=set()
        for item in (scope["Group"],scope["Worker"],scope["Freeze"],scope["Kill"],
                     *scope["Controls"].values(),*scope["WorkerControls"].values()):
            fields(item,"Device Inode")
            if any(type(v) is not int or not 0<v<2**64 for v in item.values()) or item["Device"]!=device: raise refused()
            if item["Inode"] in seen: raise refused()
            seen.add(item["Inode"])

    def _shared_ancestry(self,e,c,intent):
        """Reconstruct the fixed Go vector; never cache current ancestry or controls."""
        budget=c["host_budget"];shared=budget["shared"];root=path(budget["root"]["path"])
        start=path(shared["path"]);leaf=path(intent["SharedLeafPath"])
        if start!=root/"node" or start not in leaf.parents or len(str(leaf))>4096: raise refused()
        allocation=budget["root"]
        if e.controls(root,{"cgroup.type":"domain","memory.max":str(allocation["memory_bytes"]),"memory.swap.max":"0",
                "cpu.max":f'{allocation["cpu_millis"]*100} 100000',"cpu.max.burst":"0","pids.max":str(allocation["pids"]),
                "memory.oom.group":"1"})!={"Device":allocation["device"],"Inode":allocation["inode"]}: raise refused()
        chain=[start];current=start
        for part in leaf.relative_to(start).parts:
            current=current/part;chain.append(current)
        if not 2<=len(chain)<=128 or type(intent["SharedAncestryCount"]) is not int or intent["SharedAncestryCount"]!=len(chain): raise refused()
        keys=sorted(("cgroup.type","memory.max","memory.swap.max","cpu.max","cpu.max.burst","pids.max",
                     "cgroup.freeze","memory.high","memory.oom.group","cgroup.subtree_control"))
        shared_keys={"cgroup.type","memory.max","memory.swap.max","cpu.max","cpu.max.burst","pids.max","cgroup.freeze"}
        fields(intent["SharedControls"]," ".join(shared_keys))
        if intent["SharedBudget"]!=shared: raise refused()
        vector=[];seen=set();mounts=e.mounts()
        for index,directory in enumerate(chain):
            if any(m["path"]==str(directory) for m in mounts): raise refused()
            node=identity(e.protected(directory,directory=True))
            if node["Device"]!=budget["root"]["device"] or node["Inode"] in seen: raise refused()
            seen.add(node["Inode"]);controls={}
            for name in keys:
                raw,ident=e.read(directory/name,4096,kernel=True);value=raw.decode("ascii").strip()
                if ident["Device"]!=node["Device"]: raise refused()
                controls[name]={"Identity":ident,"Value":value}
            values={k:v["Value"] for k,v in controls.items()}
            if (values["cgroup.type"]!="domain" or values["memory.swap.max"]!="0" or values["cpu.max.burst"]!="0"
                    or values["cgroup.freeze"]!="0" or values["memory.oom.group"] not in {"0","1"}
                    or e.numbers(directory/"cgroup.events").get("frozen")!=0): raise refused()
            for name in ("memory.max","pids.max","memory.high"):
                value=values[name]
                if value!="max" and (not re.fullmatch(r"0|[1-9][0-9]*",value)
                        or not (0 if name=="memory.high" else 1)<=int(value)<=2**63-1): raise refused()
            quota=re.fullmatch(r"(max|[1-9][0-9]*) 100000",values["cpu.max"])
            if not quota or quota[1]!="max" and int(quota[1])>2**63-1: raise refused()
            if index==0:
                expected={"cgroup.type":"domain","memory.max":str(shared["memory_bytes"]),"memory.swap.max":"0",
                          "cpu.max":f'{shared["cpu_millis"]*100} 100000',"cpu.max.burst":"0","pids.max":str(shared["pids"]),"cgroup.freeze":"0"}
                if (node!={"Device":shared["device"],"Inode":shared["inode"]}
                        or any(values[k]!=v or controls[k]["Identity"]!=intent["SharedControls"][k] for k,v in expected.items())): raise refused()
            if index==len(chain)-1:
                if node!=intent["SharedLeaf"] or values["cgroup.subtree_control"] or e.names(directory,128,dirs=True): raise refused()
            elif e.text(directory/"cgroup.procs") or not {"cpu","memory","pids"}<=set(values["cgroup.subtree_control"].split()): raise refused()
            vector.append({"Path":str(directory),"Identity":node,"Controls":controls})
        # Struct declaration order, lexicographically sorted Go map keys, HTML escapes.
        raw=json.dumps(vector,separators=(",",":"),ensure_ascii=False).replace("&","\\u0026").replace("<","\\u003c").replace(">","\\u003e")
        if hashlib.sha256(raw.encode()).hexdigest()!=intent["SharedAncestrySHA256"]: raise refused()
        return vector

    def _worker_offline(self,e,c,state,records):
        directory,owner,epoch,guardian,parent,guard,limits,scope,shash=records
        if not os.path.lexists(directory/"host-worker-offline.json"): return None
        result=self._creation_record(e,directory,"host-worker-offline.json",16384);offline=result[0]
        fields(offline,"Version Guard ScopeSHA256 CreationIntentSHA256 ParentPath Parent WorkerPath Worker CreatorLock WorkerPopulated WorkerMemoryCurrent")
        expected={"Version":1,"Guard":guard,"ScopeSHA256":shash,"CreationIntentSHA256":scope["CreationIntentSHA256"],
                  "ParentPath":str(parent),"Parent":scope["Group"],"WorkerPath":scope["WorkerPath"],"Worker":scope["Worker"],
                  "CreatorLock":scope["CreatorLock"],"WorkerPopulated":0,"WorkerMemoryCurrent":offline["WorkerMemoryCurrent"]}
        if offline!=expected or type(offline["WorkerMemoryCurrent"]) is not int or not 0<=offline["WorkerMemoryCurrent"]<2**64: raise refused()
        for name,want in (("revoked.json",guard),("intent.json",guard),
                          ("retired.json",{"Guard":guard,"Group":limits["Guardian"]}),
                          ("guardian.json",{"Guard":guard,"Group":limits["Guardian"]})):
            if self._creation_record(e,directory,name)[0]!=want: raise refused()
        self._metadata(e,c,state,directory,guard)
        mounts=e.mounts()
        for title in ("Visible","Stage","Internal"):
            m=scope[title]
            if self._creation_record(e,directory,"host-unmount-"+Path(m["Path"]).name+".json")[0]!=m: raise refused()
            if any(v["path"]==m["Path"] or v["path"].startswith(m["Path"]+"/")
                   or v["id"]==m["MountID"] or v["device"]==m["Device"] for v in mounts): raise refused()
        return result

    def _host_progress(self,e,c,state,records,*,mode):
        """Only active/finite held evidence; workload retirement has its own final proof."""
        if mode not in {"active","held"}: raise refused()
        directory,owner,epoch,guardian,parent,guard,limits,scope,shash=records
        worker=path(scope["WorkerPath"]);plan=limits["Plan"]
        forbidden={"host-retired.json","host-high-intent.json","host-high-outcome.json",
                   "workload-offline.json","workload-retired.json","owner-empty.json","removed.json"}
        names=e.names(directory)
        if names&forbidden or any(name.startswith(("host-worker-","host-high-","workload-"))
                and name!="host-worker-offline.json" for name in names): raise refused()
        if mode=="active" and names&{"host-worker-offline.json","revoked.json","expired.json","retired.json",
                "host-unmount-visible.json","host-unmount-stage.json","host-unmount-internal.json"}: raise refused()
        offline=self._worker_offline(e,c,state,records)
        base={"cgroup.type":"domain","memory.max":str(plan["HostScratchBytes"]),"memory.swap.max":"0",
              "memory.oom.group":"1","pids.max":"64","cpu.max.burst":"0","cpu.max":"25000 100000","memory.high":"max"}
        e.controls(parent,base,scope["Controls"])
        raw,subtree_id=e.read(parent/"cgroup.subtree_control",4096,kernel=True)
        subtree=raw.decode("ascii").split()
        if len(subtree)!=3 or set(subtree)!={"cpu","memory","pids"} or subtree_id!=scope["Controls"]["cgroup.subtree_control"]: raise refused()
        if e.text(parent/"cgroup.procs"): raise refused()
        freeze=e.text(parent/"cgroup.freeze")
        if freeze not in ({"0"} if mode=="active" else {"1"} if offline is not None else {"0","1"}): raise refused()
        if (mode=="active" or offline is not None) and e.numbers(parent/"cgroup.events").get("frozen")!=int(freeze): raise refused()
        groups=[(parent,scope["Controls"])];exists=os.path.lexists(worker)
        if e.names(parent,dirs=True)!=({"worker"} if exists else set()): raise refused()
        if exists:
            expected={**base,"memory.max":"max","memory.oom.group":"0","cgroup.subtree_control":"","cgroup.freeze":"0"}
            if e.controls(worker,expected,scope["WorkerControls"])!=scope["Worker"] or e.names(worker,dirs=True): raise refused()
            if mode=="active" and e.numbers(worker/"cgroup.events").get("frozen")!=0: raise refused()
            groups.append((worker,scope["WorkerControls"]))
            if offline is not None and (e.numbers(worker/"cgroup.events").get("populated")!=0 or e.text(worker/"cgroup.procs")): raise refused()
        elif offline is None: raise refused()
        for group,controls in groups:
            if identity(e.protected(group/"memory.events.local"))!=controls["memory.events.local"]: raise refused()
            events=e.numbers(group/"memory.events.local")
            if any(k not in events for k in ("oom","oom_kill","oom_group_kill")): raise refused()
            if mode=="active" and any(events[k]!=0 for k in ("oom","oom_kill","oom_group_kill")): raise refused()
        return (None if offline is None else offline[0]),None,None

    def _workload_retired(self,e,c,state):
        """Versioned workload closure under the retained ancestor, never a physical-free proof."""
        self._envelope(e,c)
        records=self._record_pair(e,c,state,retired=True)
        directory,owner,epoch,guardian,host,guard,limits,scope,shash=records
        if state["host_scope_sha256"] and shash!=state["host_scope_sha256"]: raise refused()
        lock=os.open(directory/"bootstrap.lock",os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            if identity(os.fstat(lock))!=scope["CreatorLock"]: raise refused()
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            worker=self._worker_offline(e,c,state,records)
            if worker is None: raise refused()
            offline=self._creation_record(e,directory,"workload-offline.json")
            fields(offline[0],"Version Guard ScopeSHA256 CreationIntentSHA256 CreatorLock Groups")
            expected={"Version":1,"Guard":guard,"ScopeSHA256":shash,"CreationIntentSHA256":scope["CreationIntentSHA256"],
                      "CreatorLock":scope["CreatorLock"],"Groups":offline[0]["Groups"]}
            if offline[0]!=expected: raise refused()
            groups={"Owner":(owner,limits["Owner"]),"EpochParent":(epoch.parent,scope["EpochParent"]),
                    "Epoch":(epoch,limits["Epoch"]),"GuardianParent":(guardian.parent,scope["GuardianParent"]),
                    "Guardian":(guardian,limits["Guardian"]),"Host":(host,scope["Group"]),"Worker":(host/"worker",scope["Worker"])}
            fields(offline[0]["Groups"]," ".join(groups))
            for role,(_,ident) in groups.items():
                value=offline[0]["Groups"][role];fields(value,"Identity Populated MemoryCurrent")
                if (value["Identity"]!=ident or type(value["Populated"]) is not int or value["Populated"]!=0
                        or type(value["MemoryCurrent"]) is not int or not 0<=value["MemoryCurrent"]<2**64): raise refused()
            if offline[0]["Groups"]["Worker"]["MemoryCurrent"]!=worker[0]["WorkerMemoryCurrent"]: raise refused()
            terminal=self._creation_record(e,directory,"workload-retired.json")
            if terminal[0]!={"Version":1,"Guard":guard,"ScopeSHA256":shash,"CreationIntentSHA256":scope["CreationIntentSHA256"],"OfflineSHA256":offline[1]}: raise refused()
            for name in ("removed.json","owner-empty.json"):
                if self._creation_record(e,directory,name)[0]!=guard: raise refused()
            required={"bootstrap.lock","creation-intent.json","scoped-limits.json","host-scope.json","intent.json",
                      "guardian.json","retired.json","revoked.json","host-worker-offline.json","owner-empty.json","removed.json",
                      "host-unmount-visible.json","host-unmount-stage.json","host-unmount-internal.json",
                      "workload-offline.json","workload-retired.json","host"}
            optional={name+".json" for name in ("expired","primary","stock-result","runsc","cdi-hooks","runtime-refusal",
                      "runtime-bundle","runtime-release","task-create","task-unstarted","metadata-intent",
                      "host-prepare-begun","host-prepare-published","host-collect-begun","host-collect-published")}|{"control"}
            snapshot=None
            for _ in range(2):
                self._envelope(e,c)
                if self._record_pair(e,c,state,retired=True)!=records or self._worker_offline(e,c,state,records)!=worker: raise refused()
                for name in ("removed.json","owner-empty.json"):
                    if self._creation_record(e,directory,name)[0]!=guard: raise refused()
                names=e.names(directory)
                if not required<=names or names-(required|optional): raise refused()
                if "expired.json" in names and self._creation_record(e,directory,"expired.json")[0]!=guard: raise refused()
                current={}
                for name in sorted(names-{"host","control","bootstrap.lock"}):
                    info=e.protected(directory/name)
                    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600: raise refused()
                    raw,ident=e.read(directory/name,65536);current[name]=(hashlib.sha256(raw).hexdigest(),ident)
                if snapshot is not None and current!=snapshot: raise refused()
                snapshot=current
                if "control" in names:
                    info=e.protected(directory/"control")
                    if not stat.S_ISSOCK(info.st_mode) or info.st_gid!=0 or info.st_mode&0o077: raise refused()
                for backing in (directory/"host",*(directory/"host"/name for name in ("visible","stage","internal"))):
                    info=e.protected(backing,directory=True)
                    if stat.S_IMODE(info.st_mode)!=0o700 or info.st_gid!=0: raise refused()
                    if e.names(backing)!=({"visible","stage","internal"} if backing==directory/"host" else set()): raise refused()
                if any(os.path.lexists(group) for group,_ in groups.values()): raise refused()
                mounts=e.mounts()
                for m in (scope["Visible"],scope["Stage"],scope["Internal"]):
                    if any(v["id"]==m["MountID"] or v["device"]==m["Device"] or v["path"]==m["Path"]
                           or v["path"].startswith(m["Path"]+"/") for v in mounts): raise refused()
                if any(v["path"]==str(directory) or v["path"].startswith(str(directory)+"/")
                       or any(v["path"]==str(group) or v["path"].startswith(str(group)+"/") for group in (owner,host)) for v in mounts): raise refused()
                if identity(e.protected(directory/"bootstrap.lock"))!=scope["CreatorLock"]: raise refused()
                if self._creation_record(e,directory,"workload-offline.json")!=offline or self._creation_record(e,directory,"workload-retired.json")!=terminal: raise refused()
            return shash
        finally: os.close(lock)

    def _accounted_owner(self,e,c,state):
        """Prove retained finite charges, without granting creation, execution or cleanup."""
        if os.path.lexists(self._paths(c,state["binding"]["ref"])[1]/"workload-retired.json"):
            return self._workload_retired(e,c,state)
        records=self._record_pair(e,c,state)
        directory,owner,epoch,guardian,host,guard,limits,scope,actual=records
        if state["host_scope_sha256"] and actual!=state["host_scope_sha256"]: raise refused()
        task=limits["Plan"]["Task"]; plan=limits["Plan"]
        expected={"cgroup.type":"domain","memory.max":str(task["MemoryBytes"]+plan["OwnerOverheadBytes"]),
                  "memory.swap.max":"0","memory.oom.group":"1","pids.max":"512","cpu.max.burst":"0",
                  "cpu.max":f'{(task["CPUMillis"]+plan["OwnerOverheadCPUMillis"])*100} 100000'}
        if set(limits["Controls"])!=set(expected)|{"memory.events.local"}: raise refused()
        for _ in range(2):
            for name,want in (("intent.json",guard),("revoked.json",guard),("expired.json",guard),
                              ("removed.json",guard),("owner-empty.json",guard),("host-retired.json",scope),
                              ("guardian.json",{"Guard":guard,"Group":limits["Guardian"]}),
                              ("retired.json",{"Guard":guard,"Group":limits["Guardian"]})):
                if os.path.lexists(directory/name) and e.record(directory/name)[0]!=want: raise refused()
            if os.path.lexists(directory/"metadata-intent.json"):
                self._metadata(e,c,state,directory,guard)
            if self._record_pair(e,c,state)!=records: raise refused()
            e.controls(owner,expected,limits["Controls"])
            self._host_progress(e,c,state,records,mode="held")
            for group,controls in ((owner,limits["Controls"]),):
                if identity(e.protected(group/"memory.events.local"))!=controls["memory.events.local"]: raise refused()
            if (e.names(owner,dirs=True)!={"nodus-epochs","nodus-guardians"}
                    or e.names(epoch.parent,dirs=True)!={epoch.name} or e.names(guardian.parent,dirs=True)!={guardian.name}): raise refused()
            for group in (owner,epoch.parent,guardian.parent):
                if e.text(group/"cgroup.procs"): raise refused()
            for root,maximum in ((owner,512),(host,64)):
                queue=[root];count=processes=0
                while queue:
                    group=queue.pop();count+=1
                    if count>1024: raise refused()
                    queue.extend(group/name for name in e.names(group,1024,dirs=True))
                    for member in e.text(group/"cgroup.procs",16384).split():
                        processes+=1
                        if processes>maximum or e.text(f"/proc/{int(member)}/oom_score_adj")=="-1000": raise refused()
            mounts=e.mounts()
            for title in ("Visible","Stage","Internal"):
                m=scope[title]; selected=[v for v in mounts if v["path"]==m["Path"]]
                if any(v["path"].startswith(m["Path"]+"/") for v in mounts): raise refused()
                unmount=directory/("host-unmount-"+Path(m["Path"]).name+".json")
                if os.path.lexists(unmount) and e.record(unmount)[0]!=m: raise refused()
                if not selected:
                    if e.record(unmount)[0]!=m: raise refused()
                    continue
                if len(selected)!=1: raise refused()
                v=selected[0]; info=os.statvfs(m["Path"])
                options={"nodev","nosuid","noswap",f'nr_inodes={m["Inodes"]}',f'size={m["Bytes"]//1024}k'}
                if (v["id"]!=m["MountID"] or v["device"]!=m["Device"] or v["type"]!="tmpfs" or v["root"]!="/" or not options<=v["options"]
                        or identity(e.protected(m["Path"],directory=True))!=m["Identity"] or info.f_blocks*info.f_frsize!=m["Bytes"] or info.f_files!=m["Inodes"]): raise refused()
        return actual

    @staticmethod
    def _accounting_sibling(context,local_id,state):
        target=context.get("renewal_target")
        if target is None: return False
        if execution.renewal_matches(target,state,local_id): return False
        return state is not None and (state["phase"]=="creation-consumed"
            or state["phase"]=="retired" and state["phase_revision"] in {4,5})

    def _owner(self,e,c,state,*,clean=False,scope_hash=None):
        if clean: return self._workload_retired(e,c,state)
        records=self._records(e,c,state)
        directory,owner,epoch,guardian,host,guard,limits,scope,actual=records
        if scope_hash is not None and actual!=scope_hash: raise refused()
        if state["host_scope_sha256"] and actual!=state["host_scope_sha256"]: raise refused()
        task=limits["Plan"]["Task"]; plan=limits["Plan"]
        expected={"cgroup.type":"domain","memory.max":str(task["MemoryBytes"]+plan["OwnerOverheadBytes"]),
                  "memory.swap.max":"0","memory.oom.group":"1","pids.max":"512","cpu.max.burst":"0",
                  "cpu.max":f'{(task["CPUMillis"]+plan["OwnerOverheadCPUMillis"])*100} 100000'}
        if set(limits["Controls"])!=set(expected)|{"memory.events.local"}: raise refused()
        e.controls(owner,expected,limits["Controls"])
        mounts=e.mounts()
        for filename in ("revoked.json","expired.json","retired.json","removed.json"):
            if os.path.lexists(directory/filename): raise refused()
        self._host_progress(e,c,state,records,mode="active")
        if identity(e.protected(owner/"memory.events.local"))!=limits["Controls"]["memory.events.local"]: raise refused()
        events=e.numbers(owner/"memory.events.local")
        if any(events.get(key)!=0 for key in ("oom","oom_kill","oom_group_kill")): raise refused()
        for member in e.text(path(scope["WorkerPath"])/"cgroup.procs",16384).split():
            if e.text(f"/proc/{int(member)}/oom_score_adj")=="-1000": raise refused()
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

    def _retired_owner(self,e,c,state):
        # Retirement revokes execution; it does not prove an outstanding A is bounded.
        if state["phase"]!="retired" or type(state["phase_revision"]) is not int or not 2<=state["phase_revision"]<=5:
            raise refused()
        if state["phase_revision"]<=3:
            key,directory,owner,epoch,guardian,host=self._paths(c,state["binding"]["ref"])
            if any(os.path.lexists(p) for p in (directory,owner,host)): raise refused()
        elif self._has_creation_retired(c,state):
            self._creation_retired(e,c,state)
        else:
            self._owner(e,c,state,clean=True)

    def _has_creation_retired(self,c,state):
        return os.path.lexists(self._paths(c,state["binding"]["ref"])[1]/"creation-retired.json")

    def _creation_record(self,e,directory,name,limit=65536):
        info=e.protected(directory/name)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600: raise refused()
        raw,observed=e.read(directory/name,limit)
        if observed!=identity(info): raise refused()
        def integer(text):
            if not re.fullmatch(r"0|-?[1-9][0-9]*",text): raise refused()
            return int(text)
        def noninteger(_): raise refused()
        try: value=json.loads(raw,object_pairs_hook=unique,parse_int=integer,parse_float=noninteger,parse_constant=noninteger)
        except (ValueError,RecursionError): raise refused() from None
        pending=[value];count=0
        while pending:
            item=pending.pop();count+=1
            if count>512 or type(item) is bool or isinstance(item,(float,list)): raise refused()
            if isinstance(item,dict): pending.extend(item.values())
        return value,hashlib.sha256(raw).hexdigest(),observed

    def _creation_intent(self,e,c,state):
        binding=state["binding"]; lease=binding["lease"]; b=binding["host_budget"]
        if b!=c["host_budget"] or binding["runtime_identity"]!=c["runtime_identity"]: raise refused()
        who=execution.creator(state["creator"])
        if (who["executable_sha256"]!=c["creator_sha256"] or who["uid"]!=0 or who["gid"]!=0
                or any(who[k]!=b[k] for k in ("boot_id","pid_namespace","user_namespace","cgroup_namespace"))): raise refused()
        sha(state["issue_sha256"]);sha(state["start_sha256"])
        if state["issue_sha256"]==state["start_sha256"]: raise refused()
        key,directory,owner,epoch,guardian,host=self._paths(c,binding["ref"])
        topology={"Owner":str(owner),"EpochParent":str(epoch.parent),"Epoch":str(epoch),
                  "GuardianParent":str(guardian.parent),"Guardian":str(guardian),"Host":str(host),"Worker":str(host/"worker"),
                  "GuardDirectory":str(directory),"HostDirectory":str(directory/"host"),
                  "Visible":str(directory/"host/visible"),"Stage":str(directory/"host/stage"),"Internal":str(directory/"host/internal")}
        for parent in (owner.parent,host.parent,directory.parent): e.protected(parent,directory=True)
        info=e.protected(directory,directory=True)
        if stat.S_IMODE(info.st_mode)!=0o700: raise refused()
        directory_id=identity(info)
        lock_info=e.protected(directory/"bootstrap.lock")
        if not stat.S_ISREG(lock_info.st_mode) or stat.S_IMODE(lock_info.st_mode)!=0o600: raise refused()
        result=self._creation_record(e,directory,"creation-intent.json");intent=result[0]
        fields(intent,"Version Ref Namespace Executor BindingSHA256 LocalLeaseID QualificationSHA256 RunscSHA256 Creator IssueSHA256 StartSHA256 ConsumedRevision HostBudgetSHA256 HostScope TimeNamespace Shared SharedBudget Limits Plan DeadlineBootNS Directory BootstrapLock Topology")
        ch=lease["ephemeral"]["charge"]
        plan={"Version":2,"SpecSHA256":lease["ephemeral"]["spec_sha256"],"DeviceSHA256":self._grant_digest(binding),
              "VisibleBytes":lease["resources"]["scratch_bytes"],"StageBytes":ch["stage_bytes"]}
        limits={"Version":1,"BindingSHA256":state["binding_sha256"],"HostBudgetSHA256":digest(b),
                "Task":{"CPUMillis":lease["resources"]["cpu_millis"],"MemoryBytes":lease["resources"]["memory_bytes"],"PIDs":512},
                "HostScratchBytes":ch["host_memory_bytes"],"OwnerOverheadBytes":ch["owner_overhead_bytes"],"OwnerOverheadCPUMillis":ch["owner_cpu_millis"]}
        expected={"Version":2,"Ref":{"AttemptID":binding["ref"]["attempt_id"],"Epoch":binding["ref"]["epoch"]},
                  "Namespace":c["namespace"],"Executor":2,"BindingSHA256":state["binding_sha256"],"LocalLeaseID":binding["local_lease_id"],
                  "QualificationSHA256":c["runtime_identity"]["qualification_sha256"],"RunscSHA256":c["runtime_identity"]["runsc_sha256"],
                  "Creator":who,"IssueSHA256":state["issue_sha256"],"StartSHA256":state["start_sha256"],"ConsumedRevision":3,
                  "HostBudgetSHA256":digest(b),"HostScope":{"BootID":b["boot_id"],"CgroupNamespace":b["cgroup_namespace"],
                  "UserNamespace":b["user_namespace"],"PIDNamespace":b["pid_namespace"],"AllocationRoot":b["root"]["path"],
                  "AllocationDevice":b["root"]["device"],"AllocationInode":b["root"]["inode"]},
                  "TimeNamespace":os.readlink("/proc/self/ns/time"),"Shared":{"Path":b["shared"]["path"],"Device":b["shared"]["device"],"Inode":b["shared"]["inode"]},
                  "SharedBudget":b["shared"],"Limits":limits,"Plan":plan,"DeadlineBootNS":intent["DeadlineBootNS"],"Directory":directory_id,
                  "BootstrapLock":identity(lock_info),"Topology":topology}
        if type(intent["DeadlineBootNS"]) is not int or not 0<intent["DeadlineBootNS"]<=2**63-1: raise refused()
        if intent!=expected: raise refused()
        if self._creation_record(e,directory,"creation-intent.json")!=result: raise refused()
        return result

    def _creation_drain(self,e,c,directory,intent,ihash,retired):
        """Join optional original-only cleanup; neither its outcome nor absence grants execution."""
        drain=retired["Drain"]
        if drain is None:
            if any(os.path.lexists(directory/name) for name in ORIGINAL_HIGH_FILES): raise refused()
            return None
        fields(drain,"IntentSHA256 OutcomeSHA256")
        for value in drain.values(): sha(value)
        if any(os.path.lexists(directory/name) for name in ORIGINAL_HIGH_FILES[2:]): raise refused()
        high_record=self._creation_record(e,directory,ORIGINAL_HIGH_FILES[0])
        outcome_record=self._creation_record(e,directory,ORIGINAL_HIGH_FILES[1])
        high,hhash,_=high_record;outcome,ohash,_=outcome_record
        if hhash!=drain["IntentSHA256"] or ohash!=drain["OutcomeSHA256"]: raise refused()
        fields(high,"Version CreationIntentSHA256 RetiredRevision RetirementStartedBootNS DeadlineBootNS CreatorLock Targets SharedBudget SharedControls SharedLeafPath SharedLeaf SharedAncestryCount SharedAncestrySHA256 Value")
        if (high["Version"]!=1 or high["CreationIntentSHA256"]!=ihash or high["RetiredRevision"]!=4
                or high["CreatorLock"]!=intent["BootstrapLock"] or high["SharedBudget"]!=intent["SharedBudget"] or high["Value"]!=0): raise refused()
        start,end=high["RetirementStartedBootNS"],high["DeadlineBootNS"]
        if (type(start) is not int or type(end) is not int or not 0<start<end<2**63 or end-start>10_000_000_000): raise refused()
        fields(outcome,"Version IntentSHA256 WaitStatus")
        if outcome!={"Version":1,"IntentSHA256":hhash,"WaitStatus":0}: raise refused()
        sha(high["SharedAncestrySHA256"])
        ancestry=self._shared_ancestry(e,c,high)  # Exact Shared infrastructure remains live through every replay.
        budget=c["host_budget"];groups=retired["Cgroups"];limits=intent["Limits"]
        shared_ids={budget["root"]["inode"],budget["shared"]["inode"]}
        for node in ancestry:
            shared_ids.add(node["Identity"]["Inode"])
            shared_ids.update(value["Identity"]["Inode"] for value in node["Controls"].values())
        seen=shared_ids|{value["Identity"]["Inode"] for value in groups.values() if value is not None}
        fields(high["Targets"],"Host Owner")
        if all(value is None for value in high["Targets"].values()): raise refused()
        for role,target in high["Targets"].items():
            if target is None: continue
            fields(target,"Path Identity Controls");fields(target["Identity"],"Device Inode")
            if (target["Path"]!=intent["Topology"][role] or groups[role] is None
                    or target["Identity"]!=groups[role]["Identity"]
                    or target["Identity"]["Inode"] in shared_ids
                    or groups[role]["Populated"]!=0 or groups[role]["MemoryCurrent"]!=0): raise refused()
            memory=limits["HostScratchBytes"] if role=="Host" else limits["Task"]["MemoryBytes"]+limits["OwnerOverheadBytes"]
            cpu=25000 if role=="Host" else (limits["Task"]["CPUMillis"]+limits["OwnerOverheadCPUMillis"])*100
            values={"cgroup.type":"domain","cgroup.freeze":"0","cgroup.subtree_control":"cpu memory pids",
                    "memory.max":str(memory),"memory.swap.max":"0","memory.oom.group":"1","memory.high":"max",
                    "pids.max":"64" if role=="Host" else "512","cpu.max":f"{cpu} 100000","cpu.max.burst":"0"}
            fields(target["Controls"]," ".join(values))
            for name,want in values.items():
                control=target["Controls"][name];fields(control,"Identity Value");fields(control["Identity"],"Device Inode")
                ident=control["Identity"]
                if (control["Value"]!=want or any(type(v) is not int or not 0<v<2**64 for v in ident.values())
                        or ident["Device"]!=budget["root"]["device"] or ident["Inode"] in seen): raise refused()
                seen.add(ident["Inode"])
        return high_record,outcome_record

    def _creation_retired(self,e,c,state):
        """Verify a source-qualified original abort; never reconstruct its original handle."""
        if state["phase"]!="retired" or type(state["phase_revision"]) is not int or state["phase_revision"]!=4 or state["host_scope_sha256"]:
            raise refused()
        binding=state["binding"];lease=binding["lease"];b=binding["host_budget"]
        key,directory,owner,epoch,guardian,host=self._paths(c,binding["ref"])
        def number(value,maximum=2**64-1,minimum=1):
            if type(value) is not int or not minimum<=value<=maximum: raise refused()
        def file_identity(value):
            fields(value,"Device Inode")
            for v in value.values(): number(v)
        def record(name): return self._creation_record(e,directory,name)
        info=e.protected(directory,directory=True)
        if stat.S_IMODE(info.st_mode)!=0o700: raise refused()
        directory_id=identity(info)
        lock_path=directory/"bootstrap.lock";lock_info=e.protected(lock_path)
        if not stat.S_ISREG(lock_info.st_mode) or stat.S_IMODE(lock_info.st_mode)!=0o600: raise refused()
        lock=os.open(lock_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            if identity(os.fstat(lock))!=identity(lock_info): raise refused()
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            intent,ihash,iid=self._creation_intent(e,c,state)
            retired,rhash,rid=record("creation-retired.json")
            topology=intent["Topology"];limits=intent["Limits"];plan=intent["Plan"]
            fields(retired,"Version IntentSHA256 Ref BindingSHA256 LocalLeaseID Creator IssueSHA256 StartSHA256 RetiredRevision QualificationSHA256 ProofContract Cgroups Mounts OwnedDirectories Drain")
            common={k:intent[k] for k in ("Ref","BindingSHA256","LocalLeaseID","Creator","IssueSHA256","StartSHA256","QualificationSHA256")}
            common.update(Version=4,IntentSHA256=ihash,RetiredRevision=4,ProofContract="scoped-host-original-workload-abort.v4")
            if any(retired[k]!=v for k,v in common.items()) or retired["Drain"] is not None: raise refused()
            groups=retired["Cgroups"];mounts=retired["Mounts"];dirs=retired["OwnedDirectories"]
            fields(groups,"Owner EpochParent Epoch GuardianParent Guardian Host Worker")
            fields(mounts,"Visible Stage Internal");fields(dirs,"Host Visible Stage Internal")
            seen=set()
            for role,value in groups.items():
                if value is None: continue
                fields(value,"Identity Populated MemoryCurrent");file_identity(value["Identity"])
                ident=value["Identity"]
                if ident["Device"]!=b["root"]["device"] or ident["Inode"] in seen or ident["Inode"] in {b["root"]["inode"],b["shared"]["inode"]}: raise refused()
                seen.add(ident["Inode"])
                number(value["Populated"],maximum=0,minimum=0)
                number(value["MemoryCurrent"],minimum=0)
            for child,parent in (("EpochParent","Owner"),("Epoch","EpochParent"),("GuardianParent","Owner"),("Guardian","GuardianParent"),("Worker","Host")):
                if groups[child] is not None and groups[parent] is None: raise refused()
            directory_inodes={directory_id["Inode"],identity(lock_info)["Inode"]}
            for role,value in dirs.items():
                if value is not None:
                    file_identity(value)
                    if value["Device"]!=directory_id["Device"] or value["Inode"] in directory_inodes: raise refused()
                    directory_inodes.add(value["Inode"])
                    if role!="Host" and dirs["Host"] is None: raise refused()
            mount_seen=[set(),set(),set()]
            for role,size,inodes in (("Visible",plan["VisibleBytes"],256),("Stage",plan["StageBytes"],256),("Internal",8192,8)):
                m=mounts[role]
                if m is None: continue
                if dirs[role] is None or dirs["Host"] is None or groups["Host"] is None: raise refused()
                for seen,value in zip(mount_seen,self._mount(m,topology[role],size,inodes)):
                    if value in seen: raise refused()
                    seen.add(value)
            partial=None
            if os.path.lexists(directory/"scoped-limits.json"):
                partial=record("scoped-limits.json");value=partial[0]
                fields(value,"Version Root Plan Owner Epoch Guardian Controls")
                if value["Version"]!=1 or value["Root"]!=b["root"]["path"] or value["Plan"]!=limits: raise refused()
                for role in ("Owner","Epoch","Guardian"):
                    if groups[role] is None or value[role]!=groups[role]["Identity"]: raise refused()
                controls=value["Controls"]
                fields(controls,"cgroup.type cpu.max cpu.max.burst memory.max memory.swap.max memory.oom.group pids.max memory.events.local")
                control_ids={v["Identity"]["Inode"] for v in groups.values() if v is not None}|{b["root"]["inode"],b["shared"]["inode"]}
                for v in controls.values():
                    file_identity(v)
                    if v["Device"]!=b["root"]["device"] or v["Inode"] in control_ids: raise refused()
                    control_ids.add(v["Inode"])
            # No high helper or normal execution evidence can become original workload retirement.
            forbidden={"host-scope.json","metadata-intent.json","intent.json","guardian.json","revoked.json","expired.json",
                       "removed.json","owner-empty.json","host-retired.json","retired.json","control"}
            for _ in range(2):
                if e.names(directory)-{"creation-intent.json","creation-retired.json","bootstrap.lock","scoped-limits.json"}: raise refused()
                if any(os.path.lexists(directory/name) for name in forbidden): raise refused()
                if any(os.path.lexists(value) for role,value in topology.items() if role!="GuardDirectory"): raise refused()
                current=e.mounts()
                if any(v["path"]==str(directory) or v["path"].startswith(str(directory)+"/")
                       or any(v["path"]==str(p) or v["path"].startswith(str(p)+"/") for p in (owner,host)) for v in current): raise refused()
                for m in mounts.values():
                    if m is not None and any(v["id"]==m["MountID"] or v["device"]==m["Device"] for v in current): raise refused()
                if identity(e.protected(directory,directory=True))!=directory_id or identity(e.protected(lock_path))!=identity(lock_info): raise refused()
                if record("creation-intent.json")!=(intent,ihash,iid) or record("creation-retired.json")!=(retired,rhash,rid): raise refused()
                if (record("scoped-limits.json") if os.path.lexists(directory/"scoped-limits.json") else None)!=partial: raise refused()
            return ihash
        except Error as exc:
            # Shared field validators inspect protected records here, not a client request.
            if exc.code!="invalid_request" or exc.status!=400: raise
            raise refused() from None
        except OSError:
            raise refused() from None
        finally: os.close(lock)

    def _reservation(self,e,c,local,row,context):
        lease=context["lease"]; proof=decode(row["enforcement"])
        execution.qualified_proof(proof,lease)
        if (proof.get("provider_config_sha256")!=self.sha256 or proof["host_budget"]!=c["host_budget"]
                or local["id"]!=row["lease_id"] or any(row[k]!=lease["ephemeral"]["charge"]["aggregate"][k] for k in lease["resources"])): raise refused()
        self._image(e,c,proof["qualified_image"],lease)
        state=context["binding_state"]
        if state is None: return
        if state["phase"]=="retired" and self._has_creation_retired(c,state):
            self._retired_owner(e,c,state)
            return
        if self._accounting_sibling(context,local["id"],state):
            self._accounted_owner(e,c,state)
            return
        key,directory,owner,epoch,guardian,host=self._paths(c,state["binding"]["ref"])
        if state["phase"] in {"committed","creation-issued"}:
            if any(os.path.lexists(p) for p in (directory,owner,host)): raise refused()
        elif state["phase"]=="creation-consumed":
            if any(os.path.lexists(p) for p in (directory,owner,host)):
                self._owner(e,c,state)
        elif state["phase"]=="host-published": self._owner(e,c,state)
        elif state["phase"]=="retired": self._retired_owner(e,c,state)
        else: raise refused()

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
        if (capacity!=b["capacity"] or scope.get("accounting_version")!=ephemeral.ACCOUNTING
                or scope.get("purpose") not in {"admission","continuation"}
                or scope["authority_incarnation"]!=b["authority_incarnation"] or len(held)>b["max_claims"]): raise refused()
        seen=set(); expected=[set(),set(),set()]; retired=scope.get("retired",[]);target=scope.get("renewal_target")
        if target is not None and sum(execution.renewal_matches(target,item["binding_state"],item["lease"]["id"]) for item in held)!=1: raise refused()
        if not isinstance(retired,list) or len(retired)>256: raise refused()
        for item in [*held,*retired]:
            row=item.get("provider_row");state=item.get("binding_state")
            if row is None: raise refused()
            if state is None: continue
            key,directory,owner,epoch,guardian,host=self._paths(c,state["binding"]["ref"])
            if key in seen: raise refused()
            seen.add(key)
            if item in retired:
                if state["phase"]!="retired": raise refused()
            if state["phase"]=="retired" and self._has_creation_retired(c,state):
                self._retired_owner(e,c,state)
                expected[2].add(key)  # Only a verified original abort retains a guard-only name.
                continue
            if os.path.lexists(directory/"workload-retired.json"):
                if state["phase"]!="retired" and not self._accounting_sibling(scope,item["lease"]["id"],state): raise refused()
                self._workload_retired(e,c,state)
                expected[2].add(key)  # Normal closure retains history, not live cgroup names.
                continue
            if item not in retired and self._accounting_sibling(scope,item["lease"]["id"],state):
                self._accounted_owner(e,c,state)
            elif state["phase"]=="retired": self._retired_owner(e,c,state)
            # Preserve the cross-root check if a creator changed paths after reservation validation.
            if any(os.path.lexists(p) for p in (owner,host,directory)):
                for names in expected: names.add(key)
        root=path(b["root"]["path"])
        for directory,wanted in zip((root/"nodus-scoped-owners",root/"nodus-scoped-host",path(c["fifo_dir"])/"guardians"),expected):
            names=e.names(directory,320,dirs=directory != path(c["fifo_dir"])/"guardians") if directory.exists() else set()
            if names!=wanted: raise refused()
        self._envelope(e,c)
        current=self._memory_current(e,b)
        self._envelope(e,c)
        return {"contract":execution.HOST_ACCOUNTING,"host_budget":copy.deepcopy(b),"memory_current":current}

    @staticmethod
    def _memory_current(e,b):
        counter=path(b["root"]["path"])/"memory.current"
        before=identity(e.protected(counter));raw,observed=e.read(counter,128,kernel=True)
        if (before!=observed or identity(e.protected(counter))!=observed or observed["Device"]!=b["root"]["device"]
                or not re.fullmatch(rb"(?:0|[1-9][0-9]*)\n?",raw)): raise refused()
        value=int(raw)
        if not 0<=value<2**64: raise refused()
        return value

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
                self._envelope(e,c)
                if self._has_creation_retired(c,state):
                    self._retired_owner(e,c,state)
                else: self._owner(e,c,state,clean=True)
                clean=True
        return CleanupProof(clean,self.clock(),local["id"],local["generation"],tuple(local["resources"]),
                            {"provider_config_sha256":self.sha256,"workload_retirement_verified":clean,
                             "retirement_contract":"scoped-host-workload-retirement.v4"})
