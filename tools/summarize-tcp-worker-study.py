#!/usr/bin/env python3
"""Summarize complete capacity groups; keep profiling separate."""
import argparse
import json
from pathlib import Path
import statistics


def distribution(result,direction=None):
    keys=("rx_packets_v4",) if direction=="upload" else ("rx_packets_v6",) if direction=="download" else ("rx_packets_v4","rx_packets_v6")
    values=[sum(w.get(k,0) for k in keys) for w in result.get('worker_metrics') or [] if w.get('slot',0)>0]
    total=sum(values)
    return dict(shares=[v/total for v in values] if total else [],active_workers=sum(v/total>=.05 for v in values) if total else 0,
                max_share=max(values)/total if total else None,effective_workers=total*total/sum(v*v for v in values) if total else None)


def summarize(rows,rounds=3):
    rates={};identities=set()
    for row in rows:
        r=row['result']
        if not all(r.get(k) for k in ('capture_valid','workload_valid','acceptance_pass')):raise ValueError('invalid TCP capture/workload/acceptance')
        if r.get('workers')!=row['workers'] or r.get('workload_protocol')!='tcp' or r.get('perf_mode')!=row['mode']:raise ValueError('treatment metadata mismatch')
        identities.add(r['tayga_sha256'])
        if r['rate_per_flow']!='0' and r['rate_per_flow']!=0:raise ValueError('capacity was rate limited')
        key=(row['stage'],row['arm'],row['workers'],row['direction'])
        rates.setdefault(key,[]).append(row)
    if len(identities)!=1:raise ValueError('mixed executable identities')
    groups=[]
    for stage,arm,workers,direction in sorted(rates):
        selected=rates[(stage,arm,workers,direction)]
        if stage=='profile':continue
        if len(selected)!=rounds or {v['round'] for v in selected}!=set(range(1,rounds+1)):raise ValueError('incomplete or duplicated repeated group')
        mbps=[v['result']['received_mbps']/1000 for v in selected]
        dist=[distribution(v['result'],direction) for v in selected]
        groups.append(dict(stage=stage,arm=arm,workers=workers,direction=direction,median_gbps=statistics.median(mbps),min_gbps=min(mbps),max_gbps=max(mbps),
            median_max_worker_share=statistics.median(v['max_share'] for v in dist if v['max_share'] is not None),
            active_workers=[v['active_workers'] for v in dist],effective_workers=[v['effective_workers'] for v in dist]))
    expected={('ab',arm,1,d) for arm in ('before','after') for d in ('upload','download')}|{('workers','after',w,d) for w in (1,2,3) for d in ('upload','download')}
    if set(rates)-{k for k in rates if k[0]=='profile'}!=expected:raise ValueError('capacity matrix mismatch')
    profile_rows=[v for v in rows if v['stage']=='profile']
    expected_profiles={(w,s,d) for w in (1,3) for s in ('process','system') for d in ('upload','download')}
    if len(profile_rows)!=8 or {(v['workers'],v['scope'],v['direction']) for v in profile_rows}!=expected_profiles:raise ValueError('incomplete profile matrix')
    pairs=[]
    for direction in ('upload','download'):
        before={v['round']:v for v in rates[('ab','before',1,direction)]}
        after={v['round']:v for v in rates[('ab','after',1,direction)]}
        if set(before)!=set(after):raise ValueError('unpaired A/B rounds')
        changes=[100*(after[n]['result']['received_mbps']/before[n]['result']['received_mbps']-1) for n in sorted(before)]
        pairs.append(dict(direction=direction,paired_changes_percent=changes,median_paired_change_percent=statistics.median(changes)))
    return dict(tayga_sha256=next(iter(identities)),groups=groups,pairs=pairs,
                profile_cases=[dict(label=v['label'],direction=v['direction'],workers=v['workers'],scope=v['scope']) for v in rows if v['stage']=='profile'],
                runs=[dict(label=v['label'],direction=v['direction'],gbps=v['result']['received_mbps']/1000,distribution=distribution(v['result'],v['direction']),flow_tuples=v.get('flow_tuples',[])) for v in rows if v['stage']!='profile'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);a=p.parse_args()
    settings=json.loads((a.root/'settings.json').read_text());rows=json.loads((a.root/'ledger.json').read_text())
    result=summarize(rows,settings['rounds']);(a.root/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(groups=result['groups'],pairs=result['pairs']),indent=2))

if __name__=='__main__':main()
