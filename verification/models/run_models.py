#!/usr/bin/env python3
"""Run bounded exhaustive models and retain baseline/mutation receipts."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys

from allocation import AllocationModel
from checker import explore
from financial import FinancialModel
from integrated import IntegratedModel
from reclaim import ReclaimModel

ROOT=Path(__file__).resolve().parent
MODELS={model.name:model for model in (AllocationModel(),ReclaimModel(),FinancialModel(),IntegratedModel())}
MUTATIONS={
 'allocation_hierarchy':{
  'ignore_host_exclusion':'A_ExclusiveOwnership',
  'ignore_scheduler_authority':'A_ExclusiveOwnership',
  'ignore_capacity':'B_CapacityConservation',
  'ignore_trust':'G_DeclaredIsolation',
  'ignore_permission':'C_ExplicitPermissionAtAdmission',
  'ignore_owner_reservation':'E_ReservationBlocksAdmission',
  'enable_external_fractional':'ExternalFractionalDisabled'},
 'reclaim_fencing_offline':{
  'ignore_fence':'D_Fencing',
  'ignore_permission_at_launch':'C_CurrentPermissionAtPhysicalStart',
  'early_handback':'F_NoFalseHandback',
  'free_on_disconnect':'F_NoFalseHandback',
  'forget_lease_on_restart':'F_NoFalseHandback',
  'require_platform_for_local':'J_OfflineLocalManagement'},
 'cash_financial_replay':{
  'new_charge_key_on_retry':'I_ChargeIdempotency',
  'duplicate_earnings_post':'I_BalanceConservation',
  'accept_stale_settlement':'I_SettlementRevisionMonotonic',
  'non_atomic_payout_reserve':'I_NoOverPayoutReservation',
  'fresh_key_after_retry_expiry':'I_TransferIdempotency',
  'stale_bank_event_regresses':'I_HonestBankPayoutState',
  'retransfer_failed_bank_payout':'I_TransferIdempotency'},
 'lease_usage_financial_linkage':{
  'bill_allocated_but_not_running':'C_UsageRequiresAuthorizedPhysicalExecution',
  'payment_retry_restarts_work':'I_PaymentReplayCannotRestartWork',
  'lose_lineage_on_release':'I_FinancialEffectsHaveUsageLineage'}
}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=['all',*MODELS],default='all')
    parser.add_argument('--mutations',action='store_true')
    parser.add_argument('--max-states',type=int,default=1_000_000)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.max_states<1:
        parser.error('--max-states must be positive')
    started=datetime.now(timezone.utc).isoformat()
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output=args.output or ROOT/'results'/stamp
    output.mkdir(parents=True,exist_ok=False)
    sources={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(ROOT.glob('*.py'))}
    summary={'started_at_utc':started,'finished_at_utc':None,'tool':'stdlib Python exhaustive breadth-first explicit-state checker',
             'python':platform.python_version(),'source_sha256':sources,
             'command':['python3',Path(__file__).name,*sys.argv[1:]],'results':[],
             'implementation_conformance':'unverified','hardware_qualification':'unverified','processor_qualification':'unverified',
             'overall_outcome':'passed_within_declared_abstract_bounds'}
    selected=MODELS if args.profile=='all' else {args.profile:MODELS[args.profile]}
    for name,model in selected.items():
        work=[(None,None)]
        if args.mutations:
            work += list(MUTATIONS[name].items())
        for mutation,expected in work:
            result=explore(model,mutation,args.max_states)
            result['started_at_run_utc']=started
            result['source_sha256']=sources
            result['expected_mutation_property']=expected
            qualified=(result['outcome']=='passed' and result['exhaustive_search_completed']) if mutation is None else (result['outcome']=='counterexample' and expected in result['violated_properties'])
            result['run_expectation_satisfied']=qualified
            filename=name+('--'+mutation if mutation else '--baseline')+'.json'
            target=output/filename
            target.write_text(json.dumps(result,indent=2)+'\n')
            item={'profile':name,'mutation':mutation,'outcome':result['outcome'],'states':result['states_explored'],
                  'transitions':result['transitions_explored'],'expectation_satisfied':qualified,
                  'receipt':filename,'receipt_sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
            summary['results'].append(item)
            print(json.dumps(item),flush=True)
            if not qualified:
                summary['overall_outcome']='failed_or_incomplete'
    summary['finished_at_utc']=datetime.now(timezone.utc).isoformat()
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'summary':str(output/'summary.json'),'outcome':summary['overall_outcome']}),flush=True)
    return 0 if summary['overall_outcome']=='passed_within_declared_abstract_bounds' else 1


if __name__=='__main__':
    raise SystemExit(main())
