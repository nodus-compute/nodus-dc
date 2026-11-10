"""Exhaustive bounded recovery search retaining exact sources and witnesses."""
import argparse
import hashlib
import json
from pathlib import Path
from checker import explore
from native_handback_recovery import NativeRecoveryModel, MUTATIONS

EXPECTED = {
    'accept_non401': 'ReadyRequiresExactRemoteRetirementAndCleanup',
    'admit_external_after_native': 'NativeHoldNeverAdmitsExternal',
    'expiry_unlocks_native': 'NativeHoldNeverUnlocks',
    'ignore_history': 'InvalidHistoryNeverPrepares',
    'ignore_live_work': 'LiveOwnerWorkNeverPrepares',
    'infer_node_retirement_from_404': 'ReadyRequiresExactRemoteRetirementAndCleanup',
    'omit_agent_stop': 'ReadyRequiresExactRemoteRetirementAndCleanup',
    'omit_final_gpu_validation': 'ReadyRequiresExactRemoteRetirementAndCleanup',
    'omit_full_wait': 'RestartCannotReuseMonotonicWait',
    'reuse_wait_after_restart': 'RestartCannotReuseMonotonicWait',
    'accept_foreign_recovery_actor': 'RecoveryEvidenceExact',
    'accept_wrong_node_proof': 'RecoveryEvidenceExact',
    'infer_key_revocation_from_404': 'RecoveryEvidenceExact',
    'forget_unknown_recovery_delete': 'EveryIntroducedKeyRetiredBeforeReady',
    'omit_recovery_401': 'EveryIntroducedKeyRetiredBeforeReady',
    'omit_recovery_key_tracking': 'EveryIntroducedKeyRetiredBeforeReady',
    'omit_recovery_retirement': 'EveryIntroducedKeyRetiredBeforeReady',
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--max-states', type=int, default=500000)
    args = parser.parse_args()
    if args.max_states < 1:
        parser.error('--max-states must be positive')
    if set(EXPECTED) != set(MUTATIONS):
        raise ValueError('every mutation must declare its intended violated property')
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.output / 'source'
    source.mkdir()
    hashes = {}
    for name in ('checker.py', 'native_handback.py', 'native_handback_recovery.py', 'run_native_recovery.py'):
        raw = Path(__file__).with_name(name).read_bytes()
        (source/name).write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    runs = []
    for mutation in (None, *MUTATIONS):
        result = explore(NativeRecoveryModel(), mutation, max_states=args.max_states)
        result['source_sha256'] = hashes
        result['expected_mutation_property'] = EXPECTED.get(mutation)
        qualified = (result['outcome'] == 'passed' and result['exhaustive_search_completed']) if mutation is None else (
            result['outcome'] == 'counterexample' and EXPECTED[mutation] in result['violated_properties'])
        result['run_expectation_satisfied'] = qualified
        filename = ('baseline' if mutation is None else mutation) + '.json'
        (args.output/filename).write_text(json.dumps(result, indent=2) + '\n')
        runs.append({'mutation': mutation, 'outcome': result['outcome'], 'states': result['states_explored'],
                     'transitions': result['transitions_explored'], 'receipt': filename,
                     'expectation_satisfied': qualified,
                     'receipt_sha256': hashlib.sha256((args.output/filename).read_bytes()).hexdigest()})
    passed = all(r['expectation_satisfied'] for r in runs)
    summary = {'bounded_model_and_mutation_checks_passed': passed, 'implementation_conformance': False,
               'hardware_qualified': False, 'source_sha256': hashes, 'runs': runs}
    (args.output/'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
