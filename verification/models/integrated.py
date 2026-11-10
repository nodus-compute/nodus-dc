"""Small lease/physical execution -> historical usage -> financial lineage model."""
from dataclasses import dataclass, replace
from checker import Transition


@dataclass(frozen=True)
class State:
    generation: int=0
    phase: str='free'
    permission: bool=False
    connected: bool=True
    physical_generation: int=0
    owner_requested: bool=False
    owner_access: bool=False
    clean: bool=True
    usage_proofs: tuple=()
    charge_generations: tuple=()
    earnings_generations: tuple=()
    bad_usage_record: bool=False


class IntegratedModel:
    name='lease_usage_financial_linkage'
    bounds={'hosts':1,'physical_gpus':1,'lease_generations':2,'owner_requests':1,
            'qualified_usage_events_per_lease':1,'charge_and_earnings_effects_per_lease':1}
    assumptions=[
        'This coarse composition checks lineage and separation of operational/financial effects, not the full product or detailed financial model.',
        'Historical valid usage may settle after a resource is released; current lease ownership is not substituted for historical provenance.',
        'Reclaim closes usage admission in this abstraction; exact metering end boundaries require real workload and commercial-term conformance.',
        'Cleanup success is an abstract verified observation; failure preserves occupancy and quarantine.',
        'No fairness, physical kill-time, real payment or GPU isolation claim.'
    ]
    properties=['A_NoOwnerExternalOverlap','C_UsageRequiresAuthorizedPhysicalExecution','E_CleanOwnerHandback',
                'F_QuarantineNotFree','I_FinancialEffectsHaveUsageLineage','I_PaymentReplayCannotRestartWork']

    def initial(self):
        return State()

    def successors(self,s,mutation):
        yield Transition('ToggleConnection',replace(s,connected=not s.connected))
        if not s.permission:
            yield Transition('EnablePermission',replace(s,permission=True))
        else:
            phase='draining' if s.phase in ('reserved','running') else s.phase
            yield Transition('RevokePermission',replace(s,permission=False,phase=phase))
        if s.phase in ('free','released') and s.permission and s.connected and not s.owner_requested and not s.owner_access and not s.physical_generation and s.clean and s.generation<2:
            yield Transition('ReserveWholeHost',replace(s,generation=s.generation+1,phase='reserved',clean=False))
        if s.phase=='reserved' and s.permission and s.connected and not s.owner_requested and not s.physical_generation:
            yield Transition('LaunchPhysical',replace(s,phase='running',physical_generation=s.generation))
        if s.phase=='running' and s.permission and s.physical_generation==s.generation:
            yield Transition('RecordObservedUsage',replace(s,usage_proofs=tuple(sorted(set((*s.usage_proofs,s.generation))))))
        elif mutation=='bill_allocated_but_not_running' and s.phase=='reserved':
            yield Transition('UnsafeUsageFromAllocationOnly',replace(s,usage_proofs=tuple(sorted(set((*s.usage_proofs,s.generation)))),bad_usage_record=True))
        if not s.owner_requested:
            phase='draining' if s.phase in ('reserved','running') else s.phase
            yield Transition('OwnerReclaim',replace(s,owner_requested=True,phase=phase))
        if s.phase in ('draining','quarantined'):
            yield Transition('StopAndCleanupSucceeded',replace(s,physical_generation=0,clean=True,phase='released'))
            yield Transition('StopOrCleanupFailed',replace(s,phase='quarantined'))
        if s.owner_requested and s.phase in ('free','released') and s.clean and not s.physical_generation:
            yield Transition('OpenOwnerAccess',replace(s,owner_access=True))
        if s.owner_access:
            yield Transition('OwnerRelease',replace(s,owner_access=False,owner_requested=False))
        for generation in s.usage_proofs:
            yield Transition(f'ChargeHistoricalUsage:{generation}',replace(s,charge_generations=tuple(sorted(set((*s.charge_generations,generation))))))
        for generation in s.charge_generations:
            yield Transition(f'SettleHistoricalEarnings:{generation}',replace(s,earnings_generations=tuple(sorted(set((*s.earnings_generations,generation))))))
            if mutation=='payment_retry_restarts_work' and not s.physical_generation:
                yield Transition(f'UnsafePaymentRetryLaunch:{generation}',replace(s,physical_generation=generation))
            else:
                yield Transition(f'PaymentReplayNoOperationalEffect:{generation}',s)
        if mutation=='lose_lineage_on_release' and s.phase=='released' and s.usage_proofs:
            yield Transition('UnsafeDeleteReleasedUsage',replace(s,usage_proofs=()))

    def violations(self,s):
        bad=[]
        if s.owner_access and s.physical_generation:
            bad.append('A_NoOwnerExternalOverlap')
        if s.bad_usage_record:
            bad.append('C_UsageRequiresAuthorizedPhysicalExecution')
        if s.physical_generation and s.phase not in ('running','draining','quarantined'):
            bad.append('I_PaymentReplayCannotRestartWork')
        if s.owner_access and (not s.clean or s.phase not in ('free','released')):
            bad.append('E_CleanOwnerHandback')
        if not set(s.charge_generations)<=set(s.usage_proofs) or not set(s.earnings_generations)<=set(s.charge_generations):
            bad.append('I_FinancialEffectsHaveUsageLineage')
        return bad
