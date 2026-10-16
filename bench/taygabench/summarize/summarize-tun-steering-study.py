#!/usr/bin/env python3
"""Validate the frozen study matrix; distinguish capacity, loss and profiles."""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics

spec=importlib.util.spec_from_file_location('placement',Path(__file__).with_name('summarize-tcp-placement-study.py'))
placement=importlib.util.module_from_spec(spec);spec.loader.exec_module(placement)


def summarize(rows,cases,identity,streams_per_client=1):
    def key(row):return tuple(row[k] for k in ('stage','pair','binary','policy','protocol','mode','scope','direction'))
    expected={key(dict(**case,direction=d)) for case in cases for d in ('upload','download')}
    if len(expected)!=2*len(cases):raise ValueError('duplicate scheduled cases')
    seen=set();groups={};profiles=[];workload=None
    for row in rows:
        k=key(row)
        if k in seen or k not in expected:raise ValueError('unexpected or duplicate result')
        seen.add(k);r=row['result']
        if not r.get('capture_valid') or not r.get('workload_valid'):raise ValueError('invalid capture/workload')
        if row['effective']!=row['policy']:raise ValueError('unexpected steering fallback')
        if r['tayga_sha256']!=identity[row['binary']+'-tayga'] or r['clat_start_sha256']!=identity['experimental-startup.sh']:raise ValueError('binary/startup identity mismatch')
        flows=streams_per_client[row['protocol']] if isinstance(streams_per_client,dict) else streams_per_client
        if (r['workload_protocol'],r['direction'],r['perf_mode'],r['perf_scope'],r['workers'],r['clients'],r['flows_per_client'])!=(row['protocol'],row['direction'],row['mode'],row['scope'],2,4,flows):raise ValueError('treatment metadata mismatch')
        if str(r['rate_per_flow'])!='0':raise ValueError('rate-limited capacity')
        values=tuple(r.get(k) for k in ('offload_requested','offload_effective','forwarding_gro','offlink_mtu','duration_seconds','tayga_cpuset','client_cpuset','server_cpuset','guest_cpu_count'))
        if workload is None:workload=values
        if workload!=values:raise ValueError('unmatched workload configuration')
        if row['protocol']=='tcp' and row['mode']=='none' and (not r['acceptance_pass'] or row['status']!=0):raise ValueError('rejected TCP capacity')
        dist=placement.worker_summary.distribution(r,row['direction'])
        if row['mode']=='record':
            profiles.append(dict(label=row['label'],direction=row['direction'],protocol=row['protocol'],scope=row['scope'],placement=row['policy'],
                workers=2,distribution=dist,acceptance_pass=r['acceptance_pass'],degraded_reasons=r.get('degraded_reasons',[])))
        else:
            groups.setdefault((row['stage'],row['binary'],row['policy'],row['protocol'],row['direction']),[]).append(row)
    if seen!=expected:raise ValueError('incomplete frozen matrix')
    output=[]
    for (stage,binary,policy,protocol,direction),selected in sorted(groups.items()):
        selected.sort(key=lambda x:x['pair'])
        rate_key='received_active_window_mbps' if protocol=='udp' else 'received_mbps'
        rates=[x['result'][rate_key]/1000 for x in selected]
        if any(v<=0 for v in rates):raise ValueError('nonpositive delivered throughput')
        output.append(dict(stage=stage,binary=binary,policy=policy,protocol=protocol,direction=direction,median_gbps=statistics.median(rates),
            min_gbps=min(rates),max_gbps=max(rates),acceptance_pass=[x['result']['acceptance_pass'] for x in selected],
            active_workers=[placement.worker_summary.distribution(x['result'],direction)['active_workers'] for x in selected],
            median_sender_receiver_gap_percent=statistics.median(x['result']['udp_sender_receiver_gap_percent'] for x in selected) if protocol=='udp' else None,
            median_receiver_sequence_loss_percent=statistics.median(x['result']['udp_loss_percent'] for x in selected) if protocol=='udp' else None))
    pairs=[]
    for stage,protocol,direction in { (x['stage'],x['protocol'],x['direction']) for x in output if x['stage'] in ('reference','steering')}:
        left=('baseline','kernel') if stage=='reference' else ('candidate','kernel')
        right=('candidate','kernel') if stage=='reference' else ('candidate','groups')
        a={x['pair']:x for x in groups[stage,*left,protocol,direction]}
        b={x['pair']:x for x in groups[stage,*right,protocol,direction]}
        if set(a)!=set(b) or set(a)!={1,2,3}:raise ValueError('unpaired or incomplete capacity')
        field='received_active_window_mbps' if protocol=='udp' else 'received_mbps'
        changes=[100*(b[n]['result'][field]/a[n]['result'][field]-1) for n in sorted(a)]
        pairs.append(dict(stage=stage,protocol=protocol,direction=direction,paired_changes_percent=changes,median_paired_change_percent=statistics.median(changes)))
    return dict(groups=output,pairs=sorted(pairs,key=lambda x:(x['stage'],x['protocol'],x['direction'])),profiles=profiles)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);a=parser.parse_args()
    settings=json.loads((a.root/'settings.json').read_text())
    flows={'tcp':4,'udp':1} if settings.get('profiles_only') else 4 if settings.get('reference_only') else 1
    result=summarize(json.loads((a.root/'ledger.json').read_text()),json.loads((a.root/'schedule.json').read_text()),json.loads((a.root/'identity.json').read_text()),flows)
    result['profile_evidence']=placement.profile_evidence(a.root,result['profiles'])
    (a.root/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(groups=result['groups'],pairs=result['pairs']),indent=2))

if __name__=='__main__':main()
