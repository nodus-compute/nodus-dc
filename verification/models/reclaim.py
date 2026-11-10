"""Physical occupancy remains distinct from durable lease and cleanup truth."""
from dataclasses import dataclass, replace
from checker import Transition


@dataclass(frozen=True)
class State:
    generation: int=0
    phase: str='free'
    opted_in: bool=False
    owner_requested: bool=False
    owner_access: bool=False
    connected: bool=True
    agent_up: bool=True
    controller_up: bool=True
    agent_incarnation: int=0
    ttl: int=0
    physical: tuple=()
    cleanup_generation: int=-1
    validation_generation: int=-1
    retired: tuple=()
    messages: tuple=()
    local_probe: bool=False
    admission_breach: str=''
    local_blocked: bool=False


class ReclaimModel:
    name='reclaim_fencing_offline'
    bounds={'hosts':1,'physical_gpus':1,'lease_generations':2,'agent_incarnations':2,
            'deadline_ticks':2,'retained_launch_messages':4,
            'message_delivery':'Each retained message can be delivered arbitrarily often and in arbitrary order; no fairness.'}
    assumptions=[
        'Local durable lease commits and generation checks are atomic; physical GPU occupancy survives process crashes.',
        'A local authority owns each host. Remote disconnection does not imply physical termination.',
        'No new external launch while disconnected; an existing lease follows its local TTL and cannot admit after expiry.',
        'Successful stop/cleanup/validation actions represent real evidence obligations; failed cleanup and permanently disconnected/down hosts remain reachable states.',
        'Known revocation closes admissions immediately. Existing physical work may remain while draining/quarantined; no instantaneous remote physical-kill guarantee is claimed.',
        'Generation/incarnation bounds never wrap. Only two leases and one agent reincarnation are explored.',
        'Host operator and authenticated local control process are trusted; GPU hardware and driver correctness are external qualification obligations.'
    ]
    properties=['A_ExclusivePhysicalOwnership','C_CurrentPermissionAtPhysicalStart','D_Fencing',
                'E_OwnerAccessAfterCleanHandback','F_NoFalseHandback','H_CrashPreservesOccupancy','J_OfflineLocalManagement']

    def initial(self):
        return State()

    def successors(self,s,mutation):
        if s.agent_up:
            if mutation=='require_platform_for_local' and not s.connected:
                yield Transition('LocalInspectDenied',replace(s,local_blocked=True))
            else:
                yield Transition('LocalInspect',replace(s,local_probe=not s.local_probe))
        if s.connected:
            disconnected=replace(s,connected=False)
            if mutation=='free_on_disconnect' and s.phase not in ('free','released'):
                disconnected=replace(disconnected,phase='released')
            yield Transition('Disconnect',disconnected)
        else:
            yield Transition('Reconnect',replace(s,connected=True))
        if s.controller_up:
            yield Transition('CrashController',replace(s,controller_up=False))
        else:
            yield Transition('RestartController',replace(s,controller_up=True))
        if s.agent_up:
            yield Transition('CrashAgent',replace(s,agent_up=False))
        elif s.agent_incarnation<1:
            phase='quarantined' if s.phase=='starting' else s.phase
            if mutation=='forget_lease_on_restart':
                phase='released'
            yield Transition('RestartAgent',replace(s,agent_up=True,agent_incarnation=s.agent_incarnation+1,phase=phase))
        if not s.opted_in and s.agent_up:
            yield Transition('EnablePolicy',replace(s,opted_in=True))
        if s.opted_in and s.agent_up:
            phase='draining' if s.phase in ('reserved','starting','active') else s.phase
            yield Transition('RevokePolicy',replace(s,opted_in=False,phase=phase))
        if not s.owner_requested and s.agent_up:
            phase='draining' if s.phase in ('reserved','starting','active') else s.phase
            yield Transition('OwnerReclaim',replace(s,owner_requested=True,phase=phase))
        if s.owner_access:
            yield Transition('OwnerRelease',replace(s,owner_access=False,owner_requested=False))
        elif s.owner_requested and s.phase in ('free','released') and not s.physical:
            clean=s.generation==0 or (s.cleanup_generation==s.validation_generation==s.generation)
            if clean and s.agent_up:
                yield Transition('OpenOwnerAccess',replace(s,owner_access=True))
        if s.phase in ('free','released') and s.generation<2 and s.opted_in and not s.owner_requested and not s.owner_access and not s.physical and s.connected and s.agent_up and s.controller_up:
            yield Transition('ReserveExternalWholeHost',replace(s,generation=s.generation+1,phase='reserved',ttl=2,cleanup_generation=-1,validation_generation=-1))
        if s.phase=='reserved' and s.controller_up and s.connected and s.agent_up:
            message=(s.generation,s.agent_incarnation)
            yield Transition('SendLaunch',replace(s,phase='starting',messages=tuple(sorted(set((*s.messages,message))))))
        for generation,incarnation in s.messages:
            correctly_fenced=(generation==s.generation and incarnation==s.agent_incarnation and generation not in s.retired)
            permission=(s.opted_in and not s.owner_requested and not s.owner_access and s.ttl>0 and s.connected)
            phase_ok=s.phase in ('reserved','starting','active')
            if not s.agent_up or not phase_ok:
                continue
            if not correctly_fenced and mutation!='ignore_fence':
                continue
            if not permission and mutation!='ignore_permission_at_launch':
                continue
            # Duplicate launch has no second process effect for the same identity.
            if generation in s.physical:
                yield Transition('DuplicateLaunchIgnored',s)
                continue
            if s.physical and mutation!='allow_parallel_physical':
                continue
            breach=''
            if not correctly_fenced:
                breach='D_Fencing'
            elif not permission:
                breach='C_CurrentPermissionAtPhysicalStart'
            yield Transition(f'DeliverLaunch:g{generation}:i{incarnation}',replace(s,phase='active',physical=tuple(sorted((*s.physical,generation))),admission_breach=s.admission_breach or breach))
        if s.ttl>0 and s.phase not in ('free','released'):
            ttl=s.ttl-1
            phase='draining' if ttl==0 and s.phase in ('reserved','starting','active') else s.phase
            yield Transition('DeadlineTick',replace(s,ttl=ttl,phase=phase))
        if s.phase in ('draining','quarantined') and s.agent_up:
            yield Transition('StopSucceeded',replace(s,physical=(),phase='verifying',cleanup_generation=-1,validation_generation=-1))
            yield Transition('StopFailed',replace(s,phase='quarantined'))
            if mutation=='early_handback':
                yield Transition('UnsafeReleaseBeforeProof',replace(s,phase='released',owner_access=s.owner_requested))
        if s.phase=='verifying' and s.agent_up:
            if not s.physical:
                yield Transition('CleanupSucceeded',replace(s,cleanup_generation=s.generation))
            yield Transition('CleanupFailed',replace(s,phase='quarantined',cleanup_generation=-1,validation_generation=-1))
            if s.cleanup_generation==s.generation and not s.physical:
                yield Transition('ValidateSucceeded',replace(s,validation_generation=s.generation))
                yield Transition('ValidateFailed',replace(s,phase='quarantined',validation_generation=-1))
            if s.cleanup_generation==s.validation_generation==s.generation and not s.physical:
                yield Transition('ReleaseAfterProof',replace(s,phase='released',ttl=0,retired=tuple(sorted(set((*s.retired,s.generation))))))

    def violations(self,s):
        bad=[]
        if len(s.physical)>1 or (s.owner_access and s.physical):
            bad.append('A_ExclusivePhysicalOwnership')
        if s.admission_breach:
            bad.append(s.admission_breach)
        if s.phase=='released' and s.generation>0:
            if s.physical or s.cleanup_generation!=s.generation or s.validation_generation!=s.generation:
                bad.append('F_NoFalseHandback')
        if s.owner_access and (s.phase not in ('free','released') or (s.generation>0 and (s.cleanup_generation!=s.generation or s.validation_generation!=s.generation))):
            bad.append('E_OwnerAccessAfterCleanHandback')
        if s.local_blocked:
            bad.append('J_OfflineLocalManagement')
        return list(dict.fromkeys(bad))
