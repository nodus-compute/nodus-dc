"""Hierarchical host/GPU/partition allocation with trusted resource accounting."""
from dataclasses import dataclass, replace
from checker import Transition


@dataclass(frozen=True)
class Request:
    name: str
    scope: str
    mode: str
    external: bool=False
    trusted: bool=True
    memory: int=1
    compute: int=1


REQUESTS=(
    Request('owner-host','host','exclusive'),
    Request('owner-gpu0','gpu0','exclusive'),
    Request('owner-gpu1','gpu1','exclusive'),
    Request('local-part0','part0','hardware_partition'),
    Request('local-part1','part1','hardware_partition'),
    Request('local-part0-conflict','part0','hardware_partition'),
    Request('trusted-a','gpu0','trusted_cooperative'),
    Request('trusted-b','gpu0','trusted_cooperative'),
    Request('trusted-overflow','gpu0','trusted_cooperative',memory=2,compute=2),
    Request('untrusted-share','gpu0','trusted_cooperative',trusted=False),
    Request('external-host','host','exclusive',external=True),
    Request('external-fraction','part0','hardware_partition',external=True),
    Request('scheduler-gpu0-idle','gpu0','exclusive'),
    Request('invalid-profile','part-overlap','unsupported')
)

SCOPES={'host':frozenset(range(4)),'gpu0':frozenset((0,1)),
        'gpu1':frozenset((2,3)),'part0':frozenset((0,)),
        'part1':frozenset((1,)),'part-overlap':frozenset((0,1))}


@dataclass(frozen=True)
class State:
    leases: tuple=()
    opted_in: bool=False
    terms: bool=False
    owner_reserved: bool=False
    permission_breach: bool=False
    reservation_breach: bool=False


class AllocationModel:
    name='allocation_hierarchy'
    bounds={'hosts':1,'physical_gpus':2,'partition_units_per_gpu':2,
            'simultaneous_lease_slots':3,'fixed_request_descriptors':len(REQUESTS),
            'memory_and_compute_units_per_gpu':2,'external_fractional_enabled':False}
    assumptions=[
        'Abstract commit is atomic; actual database/scheduler enforcement requires separate conformance.',
        'Hardware partitions part0/part1 are disjoint qualified profiles on gpu0; other profile requests are unsupported.',
        'Trusted cooperative memory/compute budgets are declared abstract guarantees, not a claim of hardware SM or tenant isolation.',
        'An idle scheduler-held allocation is a normal authoritative allocation, independent of telemetry.',
        'No fairness. Policy can change at any state, but accepted external running lease cessation belongs to reclaim_fencing.'
    ]
    properties=['A_ExclusiveOwnership','B_CapacityConservation','C_ExplicitPermissionAtAdmission',
                'E_ReservationBlocksAdmission','G_DeclaredIsolation','SchedulerAuthorityRespected','ExternalFractionalDisabled']

    def initial(self):
        return State()

    @staticmethod
    def incompatible(a,b):
        if not (SCOPES[a.scope] & SCOPES[b.scope]):
            return False
        return not (a.mode==b.mode=='trusted_cooperative' and a.trusted and b.trusted and a.scope==b.scope)

    def admissible(self,state,index,mutation):
        request=REQUESTS[index]
        if request.mode=='unsupported':
            return False
        if request.external and request.scope!='host' and mutation!='enable_external_fractional':
            return False
        if request.mode=='trusted_cooperative' and not request.trusted and mutation!='ignore_trust':
            return False
        if request.external and (not state.opted_in or not state.terms) and mutation!='ignore_permission':
            return False
        if request.external and state.owner_reserved and mutation!='ignore_owner_reservation':
            return False
        for other_index in state.leases:
            other=REQUESTS[other_index]
            if mutation=='ignore_host_exclusion' and (request.scope=='host' or other.scope=='host'):
                continue
            if mutation=='ignore_scheduler_authority' and ('scheduler' in request.name or 'scheduler' in other.name):
                continue
            if self.incompatible(request,other):
                return False
        if request.mode=='trusted_cooperative' and mutation!='ignore_capacity':
            shares=[REQUESTS[i] for i in state.leases if REQUESTS[i].mode=='trusted_cooperative' and REQUESTS[i].scope==request.scope]
            if request.memory+sum(r.memory for r in shares)>2 or request.compute+sum(r.compute for r in shares)>2:
                return False
        return True

    def successors(self,state,mutation):
        yield Transition('ToggleOptIn',replace(state,opted_in=not state.opted_in))
        yield Transition('AcceptTerms',replace(state,terms=True))
        yield Transition('ToggleOwnerReservation',replace(state,owner_reserved=not state.owner_reserved))
        for index in state.leases:
            yield Transition('Release:'+REQUESTS[index].name,replace(state,leases=tuple(i for i in state.leases if i!=index)))
        if len(state.leases)>=3:
            return
        for index,request in enumerate(REQUESTS):
            if index in state.leases or not self.admissible(state,index,mutation):
                continue
            invalid_permission=request.external and (not state.opted_in or not state.terms)
            invalid_reservation=request.external and state.owner_reserved
            yield Transition('Commit:'+request.name,replace(state,leases=tuple(sorted((*state.leases,index))),permission_breach=state.permission_breach or invalid_permission,reservation_breach=state.reservation_breach or invalid_reservation))

    def violations(self,state):
        bad=[]
        records=[REQUESTS[i] for i in state.leases]
        if any(self.incompatible(a,b) for n,a in enumerate(records) for b in records[n+1:]):
            bad.append('A_ExclusiveOwnership')
        if any(r.external and r.scope!='host' for r in records):
            bad.append('ExternalFractionalDisabled')
        if any(r.mode=='unsupported' or (r.mode=='trusted_cooperative' and not r.trusted) for r in records):
            bad.append('G_DeclaredIsolation')
        for gpu in ('gpu0','gpu1'):
            shares=[r for r in records if r.mode=='trusted_cooperative' and r.scope==gpu]
            if sum(r.memory for r in shares)>2 or sum(r.compute for r in shares)>2:
                bad.append('B_CapacityConservation')
        if state.permission_breach:
            bad.append('C_ExplicitPermissionAtAdmission')
        if state.reservation_breach:
            bad.append('E_ReservationBlocksAdmission')
        return list(dict.fromkeys(bad))
