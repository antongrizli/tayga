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


def sample(path, steering, diagnostic=False):
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
        requested_rps=doc.get('clat_ingress_rps_cpus','unchanged')
        if requested_rps!='unchanged':
            try:
                mask_pattern=r'[0-9a-fA-F]{1,8}(,[0-9a-fA-F]{8})*'
                if not re.fullmatch(mask_pattern,requested_rps):raise ValueError('invalid RPS mask')
                evidence=load(parent.parent/'clat-ingress-rps.json')
                if (evidence.get('error') or evidence['namespace']!='clatns' or
                        evidence['interface']!='veth-nat64' or evidence['requested']!=requested_rps or
                        not evidence['queues']):
                    raise ValueError('RPS setup identity/error')
                requested_mask=int(requested_rps.replace(',',''),16)
                queues=evidence['queues']
                if len({q['queue'] for q in queues})!=len(queues):raise ValueError('duplicate RPS queue')
                for queue in queues:
                    if not re.fullmatch(r'rx-\d+',queue['queue']):raise ValueError('invalid RPS queue')
                    if not re.fullmatch(mask_pattern,queue['after']):raise ValueError('invalid RPS readback mask')
                    if int(queue['after'].replace(',',''),16)!=requested_mask:
                        raise ValueError('RPS readback mismatch')
            except (OSError,KeyError,TypeError,ValueError,AttributeError) as exc:
                errors.append('invalid/missing ingress RPS readback evidence: '+str(exc))
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
        if (session/'experiment.json').exists():
            experiment=load(session/'experiment.json')
            for key in ('experiment_id','pair_id','arm_id'):
                if not isinstance(experiment[key],str) or not experiment[key].strip():
                    raise ValueError('missing experiment identity: '+key)
            if not isinstance(experiment['harness_archive_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',experiment['harness_archive_sha256']):
                raise ValueError('invalid harness digest')
            if experiment['steering']!=steering or experiment['client_port_base']!=out['client_port_base']:
                errors.append('experiment steering/port schedule mismatch')
            harness=session/'harness-snapshot.tar.gz'
            digest=hashlib.sha256(harness.read_bytes()).hexdigest()
            if digest!=experiment['harness_archive_sha256'] or digest!=(session/'harness-snapshot.sha256').read_text().split()[0]:
                errors.append('harness archive identity mismatch')
            out['experiment']=experiment
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
        if normalized['endpoint_affinity'] not in ('off','per-client'):
            errors.append('unknown endpoint affinity policy')
        if normalized['endpoint_affinity']=='per-client':
            expected=[]
            for role in ('client','server'):
                cpus=[int(value) for value in normalized[role+'_endpoint_cpus'].split(',')]
                if not cpus or len(cpus)!=len(set(cpus)) or any(cpu<0 for cpu in cpus):
                    raise ValueError('invalid endpoint CPU list')
                expected.extend(str(cpus[i%len(cpus)]) for i in range(4))
            actors=[];current=None
            for line in (parent/'endpoint-affinity.before').read_text().splitlines():
                if line.startswith('pid='):
                    if current is not None:actors.append(current)
                    current={'pid':int(line[4:])}
                elif line.startswith('Cpus_allowed_list:') and current is not None:
                    current['cpus']=line.split(':',1)[1].strip()
            if current is not None:actors.append(current)
            if len(actors)!=8 or len({actor['pid'] for actor in actors})!=8 or any(actor['pid']<=0 for actor in actors):
                raise ValueError('missing/duplicate endpoint processes')
            if [actor['cpus'] for actor in actors]!=expected:
                errors.append('actual endpoint CPU masks differ from policy')
            out['endpoint_affinity_verified']=not any('endpoint' in error for error in errors)
        if (session/'host-power.json').exists():
            power=load(session/'host-power.json')
            if not power['before'] or power['before']!=power['after']:
                errors.append('host power changed or unavailable during session')
            if not power['settings_before'] or power['settings_before']!=power['settings_after']:
                errors.append('host power settings changed or unavailable during session')
            out['identity']['host_power_source']=power['before']
            out['identity']['host_power_settings']=power['settings_before']
        compiler=(session/'compiler.txt').read_text().strip()
        flags=(session/'build-flags.txt').read_text().strip()
        if compiler.lower() in ('','unknown','n/a') or not flags:
            raise ValueError('missing compiler/build flags')
        out['identity']['compiler']=compiler
        # The runner remaps its randomized temporary source root to '.'.
        out['identity']['build_flags']=re.sub(r'-f(file|debug|macro)-prefix-map=[^\s=]+=',r'-f\1-prefix-map=<build-root>=',flags)
    except (OSError,ValueError,KeyError,IndexError,TypeError,ZeroDivisionError,tarfile.TarError) as exc:
        errors.append(str(exc))
    quality={'daemon interval drops/errors','interface drops/errors in measured window',
             'directional worker share below 20%'}
    out['quality_errors']=[e for e in errors if e in quality]
    if diagnostic:
        errors=[e for e in errors if e not in quality]
    out['passed']=not errors
    out['errors']=errors
    return out


def evaluate(baselines, candidates, mode='configuration', repeats=5,
             download=INITIAL_DOWNLOAD_MBPS, upload=INITIAL_UPLOAD_MBPS, reduction=.45,
             diagnostic=False, baseline_steering='kernel', candidate_steering='flows'):
    arms={name:[sample(p,steering,diagnostic) for root in roots for p in sorted(root.rglob('result.json'))]
          for name,roots,steering in (('baseline',baselines,baseline_steering),('candidate',candidates,candidate_steering))}
    errors=[];groups=[]
    if not diagnostic and (baseline_steering,candidate_steering)!=('kernel','flows'):
        errors.append('product acceptance requires kernel baseline and flows candidate')
    rows=[r for rows in arms.values() for r in rows]
    explicit=diagnostic or any('experiment' in r for r in rows)
    if explicit:
        if any('experiment' not in r for r in rows):errors.append('missing experiment/harness manifest')
        experiments={r['experiment']['experiment_id'] for r in rows if 'experiment' in r}
        harnesses={r['experiment']['harness_archive_sha256'] for r in rows if 'experiment' in r}
        if len(experiments)!=1:errors.append('mixed experiment identities')
        if len(harnesses)!=1:errors.append('mixed harness identities')
        for name,rows in arms.items():
            if any(r.get('experiment',{}).get('arm_id')!=name for r in rows):
                errors.append('experiment arm mismatch: '+name)
            rows.sort(key=lambda r:(r.get('experiment',{}).get('pair_id',''),r.get('direction','')))
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
        if explicit:
            ids={arm:[r.get('experiment',{}).get('pair_id') for r in rows] for arm,rows in pair.items()}
            if ids['baseline']!=ids['candidate']:errors.append(direction+': mismatched pair identities')
            if any(len(values)!=len(set(values)) for values in ids.values()):
                errors.append(direction+': duplicate pair identity')
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
        for key in compare.WORKLOAD_KEYS+compare.TREATMENT_KEYS+('kernel_network_settings','compiler','build_flags','host_power_source','host_power_settings')+(compare.BUILD_KEYS if mode=='configuration' else ()):
            if b.get(key)!=c.get(key):errors.append(direction+': arm mismatch '+key)
        base,candidate=group['baseline'],group['candidate']
        if not diagnostic and candidate['median_mbps']<threshold:errors.append(direction+': historical throughput threshold failed')
        if not diagnostic and candidate['median_mbps']<=base['median_mbps']:
            errors.append(direction+': no same-environment throughput improvement')
        if not diagnostic and candidate['median_retransmits_per_sent_gb']>base['median_retransmits_per_sent_gb']*(1-reduction):
            errors.append(direction+': retransmissions/GB reduction failed')
        if any(b.get('client_port_base')!=c.get('client_port_base') for b,c in zip(pair['baseline'],pair['candidate'])):
            errors.append(direction+': paired flow schedules differ')
        group['paired_mbps_deltas']=[c['received_mbps']-b['received_mbps'] for b,c in zip(pair['baseline'],pair['candidate'])]
        if not diagnostic and group['paired_mbps_deltas'] and statistics.median(group['paired_mbps_deltas'])<=0:
            errors.append(direction+': no median paired throughput improvement')
        # An exact one-sided sign test guards against declaring random run-to-run
        # variation an improvement. Ties count against improvement. Five pairs
        # require five positive changes (p=1/32); larger studies use the same test.
        changes=group['paired_mbps_deltas']
        if changes:
            positive=sum(value>0 for value in changes)
            group['paired_improvement_sign_p']=sum(math.comb(len(changes),k) for k in range(positive,len(changes)+1))/2**len(changes)
            if not diagnostic and repeats>=5 and group['paired_improvement_sign_p']>.05:
                errors.append(direction+': paired improvement not established above run-to-run variation')
    return dict(passed=not errors,purpose='diagnostic' if diagnostic else 'product-acceptance',
                product_accepted=not diagnostic and not errors,mode=mode,required_repeats=repeats,groups=groups,samples=arms,errors=sorted(set(errors)),
                formulas={'received_mbps':'sum(receiver bits_per_second) / 1e6','retransmissions_per_sent_gb':'sum(sender retransmits) / (sum(sender bytes) / 1e9)'})


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',nargs='+',type=Path,required=True)
    p.add_argument('--candidate',nargs='+',type=Path,required=True)
    p.add_argument('--mode',choices=('configuration','build'),default='configuration')
    p.add_argument('--diagnostic',action='store_true',help='Validate matched evidence; never accept product performance')
    p.add_argument('--baseline-steering',choices=('kernel','groups','flows'),default='kernel')
    p.add_argument('--candidate-steering',choices=('kernel','groups','flows'),default='flows')
    p.add_argument('--min-repeats',type=int,default=5)
    p.add_argument('--download-mbps',type=float,default=INITIAL_DOWNLOAD_MBPS)
    p.add_argument('--upload-mbps',type=float,default=INITIAL_UPLOAD_MBPS)
    p.add_argument('--retransmission-reduction',type=float,default=.45)
    p.add_argument('--json',type=Path,required=True);p.add_argument('--markdown',type=Path,required=True)
    a=p.parse_args()
    report=evaluate(a.baseline,a.candidate,a.mode,a.min_repeats,a.download_mbps,a.upload_mbps,a.retransmission_reduction,
                    a.diagnostic,a.baseline_steering,a.candidate_steering)
    a.json.parent.mkdir(parents=True,exist_ok=True);a.json.write_text(json.dumps(report,indent=2)+'\n')
    status=('VALID DIAGNOSTIC; PRODUCT NOT ACCEPTED' if a.diagnostic else 'PASS') if report['passed'] else 'FAIL'
    rows=['# TCP recovery '+('diagnostic' if a.diagnostic else 'acceptance'),'', '**'+status+'**','',
          f'| Direction | Baseline ({a.baseline_steering}) median Mbps | Candidate ({a.candidate_steering}) median Mbps | Historical reference Mbps |','|---|---:|---:|---:|']
    for g in report['groups']:
        rows.append(f"| {g['direction']} | {g.get('baseline',{}).get('median_mbps','missing')} | {g.get('candidate',{}).get('median_mbps','missing')} | {g['threshold_mbps']} |")
    rows+=['','Samples, ranges, paired deltas and identities: `'+a.json.name+'`.','','Failures:','']
    rows+=['- '+e for e in report['errors']] or ['- None']
    rows+=['','Quality findings (retained even in a valid diagnostic):','']
    rows += [f"- {arm}: {r['path']}: {', '.join(r['quality_errors'])}" for arm,samples in report['samples'].items()
             for r in samples if r['quality_errors']] or ['- None']
    a.markdown.parent.mkdir(parents=True,exist_ok=True);a.markdown.write_text('\n'.join(rows)+'\n')
    print(status,a.markdown)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
