"""One CLI for studies, summaries, comparisons and memory sampling."""
import argparse
import importlib
import sys

STUDIES = {
    name: 'taygabench.studies.' + module
    for name, module in (
        ('affinity', 'run_affinity_study'), ('dispatch', 'run_dispatch_study'),
        ('iperf-read-diagnostic', 'run_iperf_read_diagnostic'), ('iperf-start', 'run_iperf_start_study'),
        ('napi', 'run_napi_study'), ('review-baseline', 'run_review_baseline'),
        ('steering-integrity', 'run_steering_integrity'), ('tcp-flow', 'run_tcp_flow_study'),
        ('tcp-worker', 'run_tcp_worker_study'), ('tun-steering', 'run_tun_steering_study'),
        ('udp-batch', 'run_udp_batch_study'), ('udp-envelope', 'run_udp_envelope_study'),
        ('controlled-ab', 'run_controlled_ab'))
}
SUMMARIES = {name: 'taygabench.summarize.summarize_' + name.replace('-', '_') + '_study'
             for name in ('tcp-flow', 'tcp-placement', 'tcp-worker', 'tun-steering', 'udp-batch')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('study', 'summarize', 'compare', 'memory'))
    raw = sys.argv[1:]
    args = parser.parse_args(raw[:1])
    remaining = raw[1:]
    if args.command in ('study', 'summarize'):
        choices = STUDIES if args.command == 'study' else SUMMARIES
        if not remaining or remaining[0] not in choices:
            parser.error('choose a name: ' + ', '.join(choices))
        module_name = choices[remaining.pop(0)]
    else:
        module_name = 'taygabench.' + args.command
    module = importlib.import_module(module_name)
    sys.argv = [module.__file__, *remaining]
    return module.main() or 0


if __name__ == '__main__':
    raise SystemExit(main())
