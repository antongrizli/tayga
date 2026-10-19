"""Bounded TCP sequence-range diagnostics, with explicit capture limitations."""
import argparse
import hashlib
import ipaddress
import json
from collections import defaultdict
from pathlib import Path

MOD = 1 << 32
HALF = MOD >> 1


def unwrap(seq, reference):
    if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < MOD:
        raise ValueError('invalid 32-bit sequence')
    if reference is None:
        return seq
    delta = (seq - reference % MOD + HALF) % MOD - HALF
    if delta == -HALF:
        raise ValueError('ambiguous sequence distance of 2^31')
    return reference + delta


def insert(intervals, start, end, limit):
    """Return new union and overlap bytes; intervals are disjoint half-open ranges."""
    overlap = sum(max(0, min(end, b) - max(start, a)) for a, b in intervals)
    merged = []
    for a, b in intervals:
        if b < start:
            merged.append((a, b))
        elif end < a:
            merged.append((start, end))
            start, end = a, b
        else:
            start, end = min(a, start), max(b, end)
    merged.append((start, end))
    if len(merged) > limit:
        raise ValueError('sequence interval budget exhausted')
    return merged, overlap


def address(value, aliases):
    parsed = str(ipaddress.ip_address(value))
    return aliases.get(parsed, parsed)


def backlog_handoffs(events, complete):
    """Match bounded skb observations; never infer packet lifetime from an address alone."""
    pending, matched = {}, defaultdict(list)
    ambiguous = unmatched_receive = 0
    fields = ('netns', 'ifindex', 'skb_addr', 'src', 'dst', 'sport', 'dport', 'seq', 'payload_len')
    for e in sorted(events, key=lambda e: e['timestamp_ns']):
        if e['stage'] not in ('backlog_enqueue', 'backlog_receive') or not e['payload_len']:
            continue
        if any(k not in e for k in fields):
            continue
        key = tuple(e[k] for k in fields)
        if e['stage'] == 'backlog_enqueue':
            pending.setdefault(key, []).append(e)
            continue
        candidates = pending.pop(key, [])
        if len(candidates) != 1:
            if candidates: ambiguous += 1
            else: unmatched_receive += 1
            continue
        enqueued = candidates[0]
        flow = tuple(enqueued[k] for k in ('netns', 'ifindex', 'src', 'dst', 'sport', 'dport'))
        matched[flow].append((enqueued, e))
    witnesses, inversions, cross_cpu = [], 0, 0
    for flow, pairs in sorted(matched.items()):
        pairs.sort(key=lambda pair: pair[0]['timestamp_ns'])
        for (ea, ra), (eb, rb) in zip(pairs, pairs[1:]):
            distance = (eb['seq'] - ea['seq']) % MOD
            size = ea['payload_len'] + int(bool(ea.get('syn'))) + int(bool(ea.get('fin')))
            if (size <= distance < HALF and ea['timestamp_ns'] < eb['timestamp_ns'] and
                    ra['timestamp_ns'] > rb['timestamp_ns']):
                inversions += 1
                different = (type(ea.get('target_cpu')) is int and type(eb.get('target_cpu')) is int and
                             ea['target_cpu'] >= 0 and eb['target_cpu'] >= 0 and
                             ea['target_cpu'] != eb['target_cpu'])
                cross_cpu += int(different)
                if len(witnesses) < 20:
                    witnesses.append(dict(flow=list(flow), a=dict(enqueue=ea, receive=ra),
                        b=dict(enqueue=eb, receive=rb), different_backlogs=different,
                        enqueue_lead_ns=eb['timestamp_ns']-ea['timestamp_ns'],
                        receive_lag_ns=ra['timestamp_ns']-rb['timestamp_ns']))
    return dict(available=bool(matched), interpretable=complete,
                matched_packets=sum(map(len, matched.values())),
                unmatched_receive=unmatched_receive, unmatched_enqueue=sum(map(len, pending.values())),
                ambiguous_matches=ambiguous, adjacent_enqueue_order_inversions=inversions,
                different_backlog_inversions=cross_cpu, witnesses=witnesses,
                limitations=['Enqueue probe is before insertion/return; receive is __netif_receive_skb entry.',
                             'Match uses namespace/interface, full tuple, skb address, sequence, size and event order.',
                             'Address reuse and concurrent timestamps preclude an unconditional lifetime or wire-order proof.',
                             'Missing receives may use unobserved list/GRO paths; never count them as packet loss.'])


def analyze(events, metadata, max_intervals=10000, max_events=500000):
    """No event count equality across segmentation; no automatic loss attribution.

    Sequence unwrapping assumes adjacent observations are less than 2^31 apart.
    A loss-free trace is necessary but insufficient to prove actual packet loss.
    """
    if len(events) > max_events:
        raise ValueError('capture exceeds analysis event budget')
    aliases = {str(ipaddress.ip_address(k)): str(ipaddress.ip_address(v))
               for k, v in metadata.get('address_aliases', {}).items()}
    groups = defaultdict(list)
    for e in events:
        for key in ('timestamp_ns', 'seq', 'payload_len', 'cpu', 'netns', 'sport', 'dport'):
            if isinstance(e[key], bool) or not isinstance(e[key], int) or e[key] < 0:
                raise ValueError('invalid event field: ' + key)
        if e['sport'] > 65535 or e['dport'] > 65535 or e['payload_len'] >= HALF:
            raise ValueError('invalid TCP range/port')
        if not isinstance(e['stage'], str) or not e['stage']:
            raise ValueError('invalid observation stage')
        if any(type(e.get(k, 0)) not in (bool, int) or e.get(k, 0) not in (0, 1) for k in ('syn', 'fin')):
            raise ValueError('invalid TCP flags')
        flow = (address(e['src'], aliases), address(e['dst'], aliases), e['sport'], e['dport'])
        groups[(e['stage'], e['netns'], e.get('ifindex', 0), flow)].append(e)
    references = {}
    for (_, _, _, flow), entries in groups.items():
        e = min(entries, key=lambda e: e['timestamp_ns'])
        if flow not in references or e['timestamp_ns'] < references[flow][0]:
            references[flow] = (e['timestamp_ns'], e['seq'])
    rows, observed = [], {}
    for (stage, netns, ifindex, flow), entries in sorted(groups.items()):
        entries.sort(key=lambda e: e['timestamp_ns'])
        intervals, high, origin = [], None, None
        timeline = []
        gaps, overlaps, filled = [], 0, 0
        tied = sum(a['timestamp_ns'] == b['timestamp_ns'] for a, b in zip(entries, entries[1:]))
        for e in entries:
            start = unwrap(e['seq'], high if high is not None else references[flow][1])
            size = e['payload_len'] + int(bool(e.get('syn'))) + int(bool(e.get('fin')))
            if not size:  # Pure ACK seq does not establish data coverage.
                continue
            end = start + size
            timeline.append((e['timestamp_ns'], start, end, e['cpu']))
            if origin is None:
                origin = start
            if high is not None and start > high:
                gaps.append(dict(start=high, end=start, timestamp_ns=e['timestamp_ns']))
            previous = intervals
            intervals, overlap = insert(intervals, start, end, max_intervals)
            overlaps += overlap
            if high is not None and start < high:
                filled += max(0, min(end, high) - start) - sum(
                    max(0, min(end, high, b) - max(start, a)) for a, b in previous)
            high = max(high if high is not None else end, end)
        missing = []
        if intervals:
            for (_, b), (a, _) in zip(intervals, intervals[1:]):
                if b < a:
                    missing.append([b, a])
        rows.append(dict(stage=stage, netns=netns, ifindex=ifindex, flow=list(flow), events=len(entries),
                         forward_gaps=gaps, unresolved_internal_ranges=missing,
                         observed_overlap_sequence_bytes=overlaps,
                         late_new_sequence_bytes=filled, timestamp_ties=tied,
                         observed_sequence_ranges=intervals,
                         starts_with_syn=bool(entries[0].get('syn'))))
        observed[(stage, netns, ifindex, flow)] = timeline
    clean = (metadata.get('complete') is True and metadata.get('lost_events') == 0 and
             metadata.get('capped_events') == 0 and not any(r['timestamp_ties'] for r in rows))
    correlations = []
    stage_rows = {(r['stage'], r['netns'], r['ifindex'], tuple(r['flow'])): r for r in rows}
    # Only explicitly supplied observation paths define adjacent pipeline points.
    # Retain candidate evidence without interpreting concurrent timestamps as wire order.
    work = 0
    for path in metadata.get('observation_paths', []):
        points = path['points']
        for upstream, downstream in zip(points, points[1:]):
            for row in rows:
                if any(row[k] != downstream[k] for k in ('stage', 'netns', 'ifindex')): continue
                key = (upstream['stage'], upstream['netns'], upstream['ifindex'], tuple(row['flow']))
                timeline = observed.get(key, [])
                upstream_gaps = stage_rows.get(key, {}).get('forward_gaps', [])
                for gap in row['forward_gaps']:
                    work += len(timeline) + len(upstream_gaps)
                    if work > 10000000: raise ValueError('cross-stage correlation budget exhausted')
                    coverage, cpus = [], set()
                    for ts, start, end, cpu in timeline:
                        if ts <= gap['timestamp_ns'] and start < gap['end'] and end > gap['start']:
                            coverage, _ = insert(coverage, max(start, gap['start']), min(end, gap['end']), max_intervals)
                            cpus.add(cpu)
                    covered = sum(b-a for a,b in coverage) == gap['end']-gap['start']
                    prior_gaps = [g for g in upstream_gaps if g['timestamp_ns'] <= gap['timestamp_ns'] and
                                  g['start'] < gap['end'] and g['end'] > gap['start']]
                    correlations.append(dict(path=path['name'], flow=row['flow'], upstream=upstream,
                        downstream=downstream, gap=gap, upstream_range_seen_before_gap=covered,
                        upstream_gap_already_observed=bool(prior_gaps), upstream_overlapping_gaps=prior_gaps,
                        upstream_cpus=sorted(cpus), capture_complete=clean,
                        attribution='overlapping gap already observed upstream; not a new handoff localization'
                                    if prior_gaps and clean else
                                    'handoff candidate; ordering/duplicate/serialization verification required'
                                    if covered and clean else 'insufficient evidence'))
    return dict(schema_version=1, purpose='sequence-diagnostic-only', product_accepted=False,
                capture_complete=clean, loss_or_reordering_proven=False,
                localization='cross-stage candidates only' if correlations else 'no localized discontinuity',
                cross_stage=correlations,
                backlog_handoffs=backlog_handoffs(events, clean),
                limitations=['Intervals measure observed sequence coverage, not unique payload bytes.',
                             'Overlap can be retransmission or capture duplication; DSACK/cross-stage evidence is required.',
                             'Unwrapping assumes adjacent sequence distances below 2^31.',
                             'Stage/CPU timestamps do not establish a global wire serialization order.',
                             'Missing prefix/suffix outside the observation window is not counted as loss.'],
                stages=rows, capture=metadata)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path, help='directory with events.jsonl and capture.json')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--max-events', type=int, default=500000)
    p.add_argument('--max-intervals', type=int, default=10000)
    p.add_argument('--aliases', type=Path, help='explicit analysis address aliases; original capture is preserved')
    p.add_argument('--paths', type=Path, help='JSON array of ordered observation paths using actual netns/ifindex')
    a = p.parse_args()
    events = []
    with (a.capture/'events.jsonl').open() as f:
        for line in f:
            if line.strip():
                if len(events) >= a.max_events:
                    p.error('capture exceeds event budget')
                events.append(json.loads(line))
    metadata = json.loads((a.capture/'capture.json').read_text())
    metadata['analysis_input_sha256'] = {
        name: hashlib.sha256((a.capture/name).read_bytes()).hexdigest()
        for name in ('events.jsonl', 'capture.json')}
    for source, key in ((a.aliases, 'address_aliases'), (a.paths, 'observation_paths')):
        if source:
            metadata[key] = json.loads(source.read_text())
            metadata['analysis_input_sha256'][str(source)] = hashlib.sha256(source.read_bytes()).hexdigest()
    result = analyze(events, metadata, a.max_intervals, a.max_events)
    result['analyzer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(result, indent=2)+'\n')
    print(f"{len(events)} events; {len(result['stages'])} stage/namespace/flow groups; complete={result['capture_complete']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
