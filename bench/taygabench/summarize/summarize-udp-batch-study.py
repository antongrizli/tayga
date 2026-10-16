#!/usr/bin/env python3
"""Validate complete native capacity matrices and summarize separate perf samples."""
import argparse
import json
from pathlib import Path
import re
import statistics


def summarize(root):
    rows=json.loads((root/'ledger.json').read_text())
    settings=json.loads((root/'settings.json').read_text())
    capacity=[r for r in rows if not r['finite'] and not r['profile']]
    expected={(pair,direction,batch,gro) for pair in range(settings['start_pair'],settings['start_pair']+settings['pairs']) for direction in ('upload','download') for batch in settings['batch_sizes'] for gro in settings['gro_values']}
    actual={}
    for r in capacity:
        match=re.fullmatch(r'pair(\d+)-(upload|download)-(\d+)-(\d+)',r['case'])
        if not match: raise ValueError('unrecognized capacity case')
        key=(int(match[1]),r['direction'],r['batch'],r['gro'])
        if key in actual: raise ValueError('duplicate capacity case')
        if not r['capture_valid'] or not r['workload_valid']: raise ValueError('invalid capacity workload')
        if r['sender']['batch']!=r['batch'] or r['receiver']['gro']!=r['gro']: raise ValueError('requested offload treatment fell back')
        if r['sender'].get('fallback_errno') or r['receiver'].get('fallback_errno'): raise ValueError('fallback during capacity case')
        actual[key]=r
    if set(actual)!=expected: raise ValueError('incomplete capacity matrix')
    identities={(r['binary_sha256'],r['endpoint_sha256']) for r in capacity}
    if len(identities)!=1: raise ValueError('mixed executable identities')
    summaries=[]
    for direction in ('upload','download'):
        for gro in settings['gro_values']:
            for batch in settings['batch_sizes']:
                group=[r for key,r in actual.items() if key[1:]==(direction,batch,gro)]
                summaries.append(dict(direction=direction,batch=batch,gro=gro,rounds=len(group),
                    received_gbps=statistics.median(r['received_mbps']/1000 for r in group),
                    offered_gbps=statistics.median(r['offered_mbps']/1000 for r in group),
                    loss_percent=statistics.median(r['loss_percent'] for r in group),
                    cpu_seconds_per_received_gib=statistics.median(r['tayga_cpu_seconds_per_received_gib'] for r in group),
                    acceptance_pass=all(r['acceptance_pass'] for r in group)))
    profiles=[]
    for row in rows:
        if not row['profile']: continue
        if not row['capture_valid'] or not row['workload_valid']: raise ValueError('invalid profile workload')
        report=(root/row['case']/'perf-report.txt').read_text()
        symbols={match[2]:float(match[1]) for match in re.finditer(r'^\s*(\d+\.\d+)%\s+\[[k.]\]\s+(\S+)',report,re.MULTILINE)}
        lost=re.search(r'Total Lost Samples:\s*(\d+)',report)
        profiles.append(dict(case=row['case'],direction=row['direction'],batch=row['batch'],gro=row['gro'],
                             lost_samples=int(lost[1]) if lost else None,self_percent=symbols,
                             cpu_seconds_per_received_gib=row['tayga_cpu_seconds_per_received_gib']))
    return dict(capacity_cases=len(capacity),finite_cases=sum(r['finite'] for r in rows),profile_cases=len(profiles),
                identities=[dict(binary_sha256=a,endpoint_sha256=b) for a,b in identities],capacity=summaries,profiles=profiles)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--output',required=True,type=Path)
    args=p.parse_args();result=summarize(args.root)
    with args.output.open('x') as output: output.write(json.dumps(result,indent=2)+'\n')
    print(f"Validated {result['capacity_cases']} capacity cases; profiles kept separate",flush=True)

if __name__=='__main__':main()
