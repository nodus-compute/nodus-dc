"""Generate a versioned dev7 through dev14 serving descriptor; never launch or allocate work."""
import argparse
import json

from nodus_dc import __version__
from nodus_dc.serving import ServingError, build_workload


NUMERICAL_PROFILES = ('default-v1', 'deterministic-v1', 'deterministic-triton-v1')


def descriptor(engine, model_directory, *, numerical_profile, network, host_port):
    if __version__ not in ('0.1.0.dev7', '0.1.0.dev8', '0.1.0.dev9', '0.1.0.dev10', '0.1.0.dev11', '0.1.0.dev12', '0.1.0.dev13', '0.1.0.dev14'):
        raise ServingError('this recipe requires nodus-datacenter 0.1.0.dev7 through 0.1.0.dev14')
    if numerical_profile not in NUMERICAL_PROFILES:
        raise ServingError('unknown numerical profile')
    if numerical_profile == 'deterministic-triton-v1' and engine != 'sglang':
        raise ServingError('deterministic-triton-v1 requires --engine sglang')
    if network not in ('loopback', 'none'):
        raise ServingError('network must be loopback or none')
    workload = build_workload(engine, model_directory, host_port=host_port)
    if numerical_profile == 'deterministic-v1':
        if engine == 'vllm':
            workload['command'].insert(0, 'VLLM_BATCH_INVARIANT=1')
        else:
            workload['command'].extend([
                '--enable-deterministic-inference', '--attention-backend', 'fa3',
            ])
    elif numerical_profile == 'deterministic-triton-v1':
        # SGLang 0.5.23 supports deterministic Triton on Ampere; FA3 targets Hopper.
        # Keep this explicit recipe separate from the historical FA3 profile.
        workload['command'].extend([
            '--enable-deterministic-inference', '--attention-backend', 'triton',
        ])
    if network == 'none':
        workload['network'] = 'none'
        del workload['ports']
    return workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=('vllm', 'sglang'), required=True)
    parser.add_argument('--model-directory', required=True)
    parser.add_argument('--numerical-profile',
                        choices=NUMERICAL_PROFILES, required=True,
                        help='deterministic-triton-v1 is SGLang-only; GPU qualification is separate')
    parser.add_argument('--network', choices=('loopback', 'none'), default='loopback')
    parser.add_argument('--host-port', type=int, default=18000)
    args = parser.parse_args()
    try:
        value = descriptor(args.engine, args.model_directory,
                           numerical_profile=args.numerical_profile,
                           network=args.network, host_port=args.host_port)
    except ServingError as exc:
        parser.error(str(exc))
    print(json.dumps(value, indent=2))


if __name__ == '__main__':
    main()
