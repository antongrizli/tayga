#!/usr/bin/env python3
"""Fail-closed TCP recovery acceptance using raw clients and synchronized snapshots."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import re
from pathlib import Path
import statistics
import tarfile
from . import compare

IDENTITY = ('pid', 'process_start_ticks', 'network_namespace', 'tun_device')
# Saved original four-client result, perf-tcp-opt-auto-lima-debian13-arm64.
# The user's no-degradation requirement is stricter than the plan's 75/70 floor.
INITIAL_DOWNLOAD_MBPS = 76177.684
INITIAL_UPLOAD_MBPS = 70638.709


def load(path):
    return json.loads(path.read_text())


def source_identity(path):
    """Reconstruct the runner's file-content identity from the saved archive."""
    tree=hashlib.sha256();seen=set()
    with tarfile.open(path,'r:gz') as archive:
        for member in sorted(archive.getmembers(),key=lambda m:m.name.removeprefix('./')):
            if not (member.isfile() or member.islnk() or member.issym()):continue
            try:payload=archive.extractfile(member)
            except KeyError:
                # Generated root symlinks may point into the excluded build dir.
                if member.islnk() or member.issym():continue
                raise
            if payload is None:continue
            name=member.name.removeprefix('./')
            if name in seen:raise ValueError('duplicate source archive member')
            seen.add(name)
            with payload: digest=hashlib.sha256(payload.read()).digest()
            tree.update(name.encode()+b'\0'+digest)
    return tree.hexdigest()


def delta(before, after, keys):
    values = {}
    for key in keys:
        a,b=before[key],after[key]
        if not isinstance(a,(int,float)) or not isinstance(b,(int,float)) or not math.isfinite(a) or not math.isfinite(b) or a<0 or b<a:
            raise ValueError('counter reset/invalid: '+key)
        values[key]=b-a
    return values


def sample(path, steering):
    """Retain every rejected sample with reasons; never select only good runs."""
    errors=[]; out={'path':str(path), 'passed':False}
    try:
        doc=load(path);out['direction']=doc['direction']
        if doc['direction'] not in ('download','upload'):errors.append('unsupported direction')
        if not doc.get('capture_valid') or not doc.get('workload_valid'):
            errors.append('capture/workload invalid')
        if doc['workload_protocol']!='tcp': errors.append('TCP required')
        if doc['clients']!=4 or doc['expected_clients']!=4: errors.append('four clients required')
        if doc['flows_per_client']!=1 or str(doc['rate_per_flow'])!='0':
            errors.append('one unlimited flow per client required')
        if doc['offlink_mtu']!=1280 or doc['offload_requested']!='auto' or doc['offload_effective'] not in ('tcp','udp'):
            errors.append('MTU 1280 and negotiated auto offload required')
        if doc['workers']!=3 or doc['duration_seconds']!=20 or doc['warmup_seconds']!=5:
            errors.append('expected three workers, 20s duration and 5s warmup')
        if doc['perf_mode']!='none': errors.append('uninstrumented perf_mode=none required')
        out['client_port_base']=doc.get('client_port_base',0)
        if not isinstance(out['client_port_base'],int) or not 1024<=out['client_port_base']<=62530:
            errors.append('valid deterministic client port base required')
        parent=path.parent
        network=[]
        network_keys={'net.core.netdev_max_backlog','net.core.netdev_budget','net.core.netdev_budget_usecs'}
        for phase in ('before','after'):
            settings=dict(line.split(' = ',1) for line in (parent/f'kernel-network-settings.{phase}').read_text().splitlines())
            if set(settings)!=network_keys or any(int(v)<0 for v in settings.values()):
                raise ValueError('missing/invalid kernel network settings')
            network.append(settings)
        if network[0]!=network[1]:errors.append('kernel network settings changed during capture')
        before,after=(load(parent/f'tayga-status.{phase}.json') for phase in ('before','after'))
        if any(before[k]!=after[k] for k in IDENTITY): errors.append('daemon identity changed')
        if not all(s.get('workers_synced') and not s.get('unacknowledged_worker_slots') for s in (before,after)):
            errors.append('worker snapshots not synchronized')
        if after['snapshot_sequence']<=before['snapshot_sequence']: errors.append('stale snapshots')
        for snap in (before,after):
            if snap['steering_effective']!=steering or snap['steering_requested']!=steering:
                errors.append('wrong requested/effective steering')
            if snap['packet_io']!='sync' or snap['dispatch_mode']!='kernel': errors.append('wrong I/O/dispatch backend')
            if snap['offload_effective']!=doc['offload_effective']:errors.append('offload identity mismatch')
        traffic=delta(before['traffic'],after['traffic'],('dropped_packets','errors'))
        failures=delta(before,after,('tx_failed_frames','tx_short','tx_fatal','async_errors','dispatch_drops'))
        gso=delta(before['gso'],after['gso'],('invalid_packets','tun_write_errors'))
        if any(traffic.values()) or any(failures.values()) or any(gso.values()): errors.append('daemon interval drops/errors')
        worker_key='rx_packets_v6' if doc['direction']=='download' else 'rx_packets_v4'
        workers=[];bslots={w['slot']:w for w in before['workers'] if w['slot']>0}
        aslots={w['slot']:w for w in after['workers'] if w['slot']>0}
        if len(bslots)!=3 or set(bslots)!=set(aslots): raise ValueError('missing/mismatched worker slots')
        for slot in sorted(bslots):workers.append(delta(bslots[slot],aslots[slot],(worker_key,))[worker_key])
        out['worker_packets']=workers
        out['worker_shares']=[x/sum(workers) if sum(workers) else 0 for x in workers]
        # This is a traffic-share gate, not proof of an exact flow distribution.
        if steering=='flows' and min(out['worker_shares'])<.20:errors.append('directional worker share below 20%')
        interfaces=doc['interface_deltas']
        if not interfaces: raise ValueError('missing interface drop evidence')
        drops=0
        for links in interfaces.values():
            for counters in links.values():
                for way in ('rx','tx'):
                    for kind in ('dropped','errors'):
                        value=counters[way][kind]
                        if value<0:raise ValueError('interface counter reset')
                        drops+=value
        out['interface_drops_and_errors']=drops
        if drops:errors.append('interface drops/errors in measured window')
        files=sorted(parent.glob('client-*.json'))
        if len(files)!=4: raise ValueError('missing/extra raw client reports')
        mbps=sent=retrans=0
        for number,file in enumerate(files,1):
            client=load(file)
            if client.get('error'):raise ValueError('client error')
            start=client['start']['test_start']
            if (start['protocol']!='TCP' or start['num_streams']!=1 or start['duration']!=20 or
                start['target_bitrate']!=0 or start['bidir'] or
                start['reverse']!=(1 if doc['direction']=='download' else 0)):
                errors.append('raw client workload/direction mismatch')
            connected=client['start']['connected']
            expected_port=out['client_port_base']+number+(1000 if doc['direction']=='upload' else 0)
            if len(connected)!=1 or connected[0]['local_port']!=expected_port:
                errors.append('raw client data port schedule mismatch')
            end=client['end'];recv=end['sum_received'];send=end['sum_sent']
            if not 19 <= recv['seconds'] <= 22:errors.append('client duration mismatch')
            values=(recv['bits_per_second'],send['bytes'],send['retransmits'])
            if any(not isinstance(v,(int,float)) or not math.isfinite(v) or v<0 for v in values):
                raise ValueError('invalid raw client metric')
            mbps+=recv['bits_per_second']/1e6;sent+=send['bytes'];retrans+=send['retransmits']
        if sent<=0:raise ValueError('no sender bytes')
        out.update(received_mbps=mbps,sent_bytes=sent,retransmits=retrans,
                   retransmits_per_sent_gb=retrans/(sent/1e9))
        if not math.isfinite(mbps) or abs(mbps-doc['received_mbps'])>max(1,mbps*.001):errors.append('raw/summary throughput mismatch')
        # Require recorded content identities, not just a revision from a dirty tree.
        session=parent.parent.parent
        for key,file in (('source_tree_sha256','source-tree.sha256'),('tayga_sha256','tayga.sha256')):
            recorded=(session/file).read_text().split()[0]
            if not recorded or recorded!=doc[key]:errors.append(key+' manifest mismatch')
        archive=session/'source-snapshot.tar.gz'
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=(session/'source-snapshot.sha256').read_text().split()[0]:
            errors.append('source archive digest mismatch')
        if source_identity(archive)!=doc['source_tree_sha256']:
            errors.append('source archive contents/identity mismatch')
        # Reuse compatibility defaults already defined by the comparison tool.
        normalized=next(r for r in compare.results(parent) if r['path']==str(path))
        out['identity']={k:normalized.get(k) for k in compare.WORKLOAD_KEYS+compare.BUILD_KEYS+compare.TREATMENT_KEYS}
        out['identity']['kernel_network_settings']=network[0]
        compiler=(session/'compiler.txt').read_text().strip()
        flags=(session/'build-flags.txt').read_text().strip()
        if compiler.lower() in ('','unknown','n/a') or not flags:
            raise ValueError('missing compiler/build flags')
        out['identity']['compiler']=compiler
        # The runner remaps its randomized temporary source root to '.'.
        out['identity']['build_flags']=re.sub(r'-f(file|debug|macro)-prefix-map=[^\s=]+=',r'-f\1-prefix-map=<build-root>=',flags)
        out['passed']=not errors
    except (OSError,ValueError,KeyError,IndexError,TypeError,ZeroDivisionError,tarfile.TarError) as exc:
        errors.append(str(exc))
    out['errors']=errors
    return out


def evaluate(baselines, candidates, mode='configuration', repeats=5,
             download=INITIAL_DOWNLOAD_MBPS, upload=INITIAL_UPLOAD_MBPS, reduction=.45):
    arms={name:[sample(p,steering) for root in roots for p in sorted(root.rglob('result.json'))]
          for name,roots,steering in (('baseline',baselines,'kernel'),('candidate',candidates,'flows'))}
    errors=[];groups=[]
    paths=[Path(row['path']).resolve() for rows in arms.values() for row in rows]
    if len(paths)!=len(set(paths)):
        errors.append('duplicate samples cannot count as independent trials')
    if repeats<1: raise ValueError('repeats must be positive')
    if any(not math.isfinite(v) or v<0 for v in (download,upload)):raise ValueError('thresholds must be finite and nonnegative')
    if not 0<=reduction<=1:raise ValueError('reduction must lie in [0,1]')
    for arm,rows in arms.items():
        if not rows:errors.append(arm+': no samples')
        for row in rows:
            if not row['passed']:errors.append(arm+': '+row['path']+': '+', '.join(row['errors']))
    for direction,threshold in (('download',download),('upload',upload)):
        pair={arm:[r for r in rows if r.get('direction')==direction] for arm,rows in arms.items()}
        group={'direction':direction,'threshold_mbps':threshold};groups.append(group)
        if any(len(rows)<repeats for rows in pair.values()):errors.append(direction+': insufficient paired repeats')
        if len(pair['baseline'])!=len(pair['candidate']):errors.append(direction+': unpaired sample counts')
        for arm,rows in pair.items():
            if not rows or any('identity' not in r for r in rows):continue
            keys=compare.WORKLOAD_KEYS+compare.TREATMENT_KEYS+compare.BUILD_KEYS
            ids={json.dumps(r['identity'],sort_keys=True) for r in rows}
            if len(ids)!=1:errors.append(direction+': mixed settings/builds within '+arm)
            for row in rows:
                for key in keys:
                    if (row['identity'].get(key) is None and key not in compare.OPTIONAL_IDENTITY_KEYS) or (isinstance(row['identity'].get(key),str) and row['identity'][key].strip().lower() in ('','unknown','n/a')):
                        errors.append(direction+': missing identity '+key)
            values=[r['received_mbps'] for r in rows]
            group[arm]={'n':len(values),'median_mbps':statistics.median(values),'min_mbps':min(values),'max_mbps':max(values),
                        'median_retransmits_per_sent_gb':statistics.median(r['retransmits_per_sent_gb'] for r in rows)}
        if not all(k in group for k in ('baseline','candidate')):continue
        b,c=pair['baseline'][0]['identity'],pair['candidate'][0]['identity']
        for key in compare.WORKLOAD_KEYS+compare.TREATMENT_KEYS+('kernel_network_settings','compiler','build_flags')+(compare.BUILD_KEYS if mode=='configuration' else ()):
            if b.get(key)!=c.get(key):errors.append(direction+': arm mismatch '+key)
        base,candidate=group['baseline'],group['candidate']
        if candidate['median_mbps']<threshold:errors.append(direction+': historical throughput threshold failed')
        if candidate['median_mbps']<=base['median_mbps']:
            errors.append(direction+': no same-environment throughput improvement')
        if candidate['median_retransmits_per_sent_gb']>base['median_retransmits_per_sent_gb']*(1-reduction):
            errors.append(direction+': retransmissions/GB reduction failed')
        if any(b.get('client_port_base')!=c.get('client_port_base') for b,c in zip(pair['baseline'],pair['candidate'])):
            errors.append(direction+': paired flow schedules differ')
        group['paired_mbps_deltas']=[c['received_mbps']-b['received_mbps'] for b,c in zip(pair['baseline'],pair['candidate'])]
        if group['paired_mbps_deltas'] and statistics.median(group['paired_mbps_deltas'])<=0:
            errors.append(direction+': no median paired throughput improvement')
        # An exact one-sided sign test guards against declaring random run-to-run
        # variation an improvement. Ties count against improvement. Five pairs
        # require five positive changes (p=1/32); larger studies use the same test.
        changes=group['paired_mbps_deltas']
        if changes:
            positive=sum(value>0 for value in changes)
            group['paired_improvement_sign_p']=sum(math.comb(len(changes),k) for k in range(positive,len(changes)+1))/2**len(changes)
            if repeats>=5 and group['paired_improvement_sign_p']>.05:
                errors.append(direction+': paired improvement not established above run-to-run variation')
    return dict(passed=not errors,mode=mode,required_repeats=repeats,groups=groups,samples=arms,errors=sorted(set(errors)),
                formulas={'received_mbps':'sum(receiver bits_per_second) / 1e6','retransmissions_per_sent_gb':'sum(sender retransmits) / (sum(sender bytes) / 1e9)'})


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',nargs='+',type=Path,required=True)
    p.add_argument('--candidate',nargs='+',type=Path,required=True)
    p.add_argument('--mode',choices=('configuration','build'),default='configuration')
    p.add_argument('--min-repeats',type=int,default=5)
    p.add_argument('--download-mbps',type=float,default=INITIAL_DOWNLOAD_MBPS)
    p.add_argument('--upload-mbps',type=float,default=INITIAL_UPLOAD_MBPS)
    p.add_argument('--retransmission-reduction',type=float,default=.45)
    p.add_argument('--json',type=Path,required=True);p.add_argument('--markdown',type=Path,required=True)
    a=p.parse_args()
    report=evaluate(a.baseline,a.candidate,a.mode,a.min_repeats,a.download_mbps,a.upload_mbps,a.retransmission_reduction)
    a.json.parent.mkdir(parents=True,exist_ok=True);a.json.write_text(json.dumps(report,indent=2)+'\n')
    rows=['# TCP recovery acceptance','', '**'+('PASS' if report['passed'] else 'FAIL')+'**','',
          '| Direction | Kernel median Mbps | Flows median Mbps | Target Mbps |','|---|---:|---:|---:|']
    for g in report['groups']:
        rows.append(f"| {g['direction']} | {g.get('baseline',{}).get('median_mbps','missing')} | {g.get('candidate',{}).get('median_mbps','missing')} | {g['threshold_mbps']} |")
    rows+=['','Samples, ranges, paired deltas and identities: `'+a.json.name+'`.','','Failures:','']
    rows+=['- '+e for e in report['errors']] or ['- None']
    a.markdown.parent.mkdir(parents=True,exist_ok=True);a.markdown.write_text('\n'.join(rows)+'\n')
    print('PASS' if report['passed'] else 'FAIL',a.markdown)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
