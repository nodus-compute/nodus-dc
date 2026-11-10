"""Exhaustive bounded schema3 extension; retained sources and exact witnesses."""
import argparse
import hashlib
import json
from pathlib import Path
from checker import explore
from native_observation import NativeObservationModel, ORIGINS, MUTATIONS, INHERITED_NEVER_ROUTE_MUTANTS


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--max-states', type=int, default=500000)
    a = p.parse_args()
    if a.max_states < 1: p.error('positive exploration guard required')
    a.output.mkdir(parents=True, exist_ok=False); (a.output/'source').mkdir()
    hashes = {}
    for n in ('checker.py', 'native_handback.py', 'native_handback_recovery.py',
              'native_observation.py', 'run_native_observation.py'):
        raw = Path(__file__).with_name(n).read_bytes(); (a.output/'source'/n).write_bytes(raw)
        hashes[n] = hashlib.sha256(raw).hexdigest()
    runs = []; passed = True
    jobs = [(origin, None, None) for origin in ORIGINS] + [(origin, mutant, expected) for mutant, (origin, expected) in MUTATIONS.items()]
    for origin, mutant, expected in jobs:
        result = explore(NativeObservationModel(origin), mutant, max_states=a.max_states)
        result['source_sha256'] = hashes
        valid = (result['outcome'] == 'passed' and result['exhaustive_search_completed']) if mutant is None else (result['outcome'] == 'counterexample' and expected in result['violated_properties'])
        if mutant in INHERITED_NEVER_ROUTE_MUTANTS:
            valid &= any(step['action'] == 'PersistNeverParticipatedNativeIntent' for step in result['counterexample'])
            result['required_witness_route'] = 'never_enabled'
        passed &= valid
        name = (mutant or 'baseline-'+origin)+'.json'
        (a.output/name).write_text(json.dumps(result, indent=2)+'\n')
        runs.append({'origin': origin, 'mutation': mutant, 'expected_property': expected,
            'expected_result_observed': valid, 'outcome': result['outcome'],
            'states': result['states_explored'], 'transitions': result['transitions_explored'], 'receipt': name})
    summary = {'bounded_checks_passed': passed, 'source_sha256': hashes, 'runs': runs,
        'implementation_conformance': False, 'hardware_qualified': False,
        'claim': 'Only exhaustive safety of each finite selected-origin model and intended omission counterexamples; no refinement or liveness proof.'}
    (a.output/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
