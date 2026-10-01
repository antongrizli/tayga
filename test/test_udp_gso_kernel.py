#!/usr/bin/env python3
"""Real Linux TUN UDP_SEGMENT tests with independent post-segmentation checks.

Run as root on Linux. Uses isolated namespaces and an explicitly selected binary;
does not install it. Receiver offloads are disabled only on disposable test links.
Each case saves the wire capture, receiver result, sender count, and GSO deltas.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time

UDP_SEGMENT = 103
SO_RXQ_OVFL = 40
PORT = 49152
ADDR4 = "192.0.2.2"
ADDR6 = "2001:db8:64::2"
PEER4 = "198.51.100.2"
PEER6 = "64:ff9b::c633:6402"


def payloads(spec):
    return [bytes((i * 37 + j) % 251 for j in range(n))
            for i, n in enumerate(spec["lengths"])]


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def validate_frame(frame, family, expected_src, expected_dst):
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    ip = frame[14:]
    if family == 4:
        if ethertype != 0x0800 or len(ip) < 28 or ip[9] != 17:
            return None
        hlen = (ip[0] & 15) * 4
        total, ident, flags = struct.unpack_from("!HHH", ip, 2)
        assert hlen >= 20 and total <= len(ip), "truncated IPv4 capture"
        assert checksum(ip[:hlen]) == 0, "IPv4 header checksum"
        assert not flags & 0x3fff, "unexpected IPv4 fragment"
        src, dst = socket.inet_ntop(socket.AF_INET, ip[12:16]), socket.inet_ntop(socket.AF_INET, ip[16:20])
        udp = ip[hlen:total]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, len(udp))
        policy = {"ipv4_length": total, "ipv4_id": ident, "df": bool(flags & 0x4000)}
        ttl = ip[8]
    else:
        if ethertype != 0x86dd or len(ip) < 48 or ip[6] != 17:
            return None
        length = struct.unpack_from("!H", ip, 4)[0]
        assert 40 + length <= len(ip), "truncated IPv6 capture"
        src, dst = socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40])
        udp = ip[40:40 + length]
        pseudo = ip[8:40] + struct.pack("!I3xB", len(udp), 17)
        policy = {}
        ttl = ip[7]
    if len(udp) < 8 or struct.unpack_from("!H", udp, 2)[0] != PORT:
        return None
    assert src == expected_src and dst == expected_dst, (src, dst)
    assert struct.unpack_from("!H", udp, 4)[0] == len(udp), "per-datagram UDP length"
    assert udp[6:8] != b"\0\0" and checksum(pseudo + udp) == 0, "completed UDP checksum"
    # Local sender -> TAYGA translation -> one kernel forwarding hop to veth.
    assert ttl == 62, ("TTL/hop limit", ttl)
    if family == 4:
        assert policy["df"] == (policy["ipv4_length"] > 1260), policy
        # RFC 6864: atomic datagram IDs have no reassembly meaning. Linux
        # increments the aggregate's initial ID when completing UDP GSO.
    return udp[8:], policy


def endpoint(kind, spec_path):
    spec = json.loads(Path(spec_path).read_text())
    expected = payloads(spec)
    family = socket.AF_INET if spec["family"] == 4 else socket.AF_INET6
    with socket.socket(family, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        if kind == "send":
            udp.bind((spec["source"], 0))
            udp.setsockopt(socket.IPPROTO_IP if family == socket.AF_INET else socket.IPPROTO_IPV6,
                           socket.IP_TTL if family == socket.AF_INET else socket.IPV6_UNICAST_HOPS, 64)
            if spec["segmented"]:
                aggregate = b"".join(expected)
                sent = udp.sendmsg([aggregate], [(17, UDP_SEGMENT, struct.pack("=H", spec["lengths"][0]))],
                                   0, (spec["destination"], PORT))
                assert sent == len(aggregate)
            else:
                for data in expected:
                    assert udp.sendto(data, (spec["destination"], PORT)) == len(data)
            print(json.dumps({"sent_datagrams": len(expected), "sent_bytes": sum(map(len, expected))}))
            return
        udp.bind((spec["destination"], PORT))
        udp.setsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL, 1)
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        raw.bind(("ep0", 0))
        udp.setblocking(False)
        raw.setblocking(False)
        packets, received, policies, frames = [], [], [], []
        overflow = None
        print("READY", flush=True)
        deadline = time.monotonic() + 4
        drained = False
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([udp, raw], [], [], 0.05)
                for fd in readable:
                    if fd is udp:
                        data, anc, flags, _ = udp.recvmsg(65536, 256)
                        assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                        received.append(data)
                        for level, kind, value in anc:
                            if level == socket.SOL_SOCKET and kind == SO_RXQ_OVFL:
                                overflow = struct.unpack("=I", value)[0]
                    else:
                        frame = raw.recv(131072)
                        if len(frame) < 14:
                            continue
                        checked = validate_frame(frame, spec["family"], spec["source"], spec["destination"])
                        if checked is not None:
                            data, policy = checked
                            packets.append(data)
                            policies.append(policy)
                            frames.append(frame)
                if len(received) >= len(expected) and len(packets) >= len(expected) and not drained:
                    deadline = time.monotonic() + 0.1
                    drained = True
            assert received == expected, ("socket payloads/order/count", list(map(len, received)), spec["lengths"])
            assert packets == expected, ("wire payloads/order/count", list(map(len, packets)), spec["lengths"])
            ids = [p["ipv4_id"] for p in policies if p and not p["df"]]
            assert len(set(ids)) == len(ids), ("duplicate small-packet IPv4 IDs", ids)
            assert all(b == (a + 1) % 65536 for a, b in zip(ids, ids[1:])), ("nonconsecutive IPv4 IDs", ids)
            result = {"passed": True, "received_datagrams": len(received), "wire_datagrams": len(packets),
                      "wire_policy": policies, "socket_overflow_option_enabled": True,
                      "socket_overflow_last_ancillary_value": overflow}
            Path(spec["output"]).write_text(json.dumps(result, indent=2) + "\n")
        finally:
            raw.close()
            # PCAP LINKTYPE_ETHERNET, captured after software segmentation and completion.
            with open(spec["pcap"], "wb") as out:
                out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 131072, 1))
                for frame in frames:
                    out.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
                    out.write(frame)


def command(*args, check=True):
    return subprocess.run([str(x) for x in args], check=check, capture_output=True, text=True, timeout=10)


def ns_command(ns, *args):
    return command("ip", "netns", "exec", ns, *args)


def gso_stats(log):
    lines = re.findall(r"GSO Stats: ([^\n]+)", log.read_text())
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", lines[-1])} if lines else {}


def run_group(args, mode, workers, mtu, direction, root):
    group = root / f"{mode}-w{workers}-mtu{mtu}-{direction}"
    group.mkdir()
    stem = f"tguso-{os.getpid()}"
    trans, recv = stem + "t", stem + "r"
    daemon = None
    log = group / "tayga.log"
    log_fd = log.open("w")
    try:
        for ns in (trans, recv):
            command("ip", "netns", "add", ns)
            command("ip", "-n", ns, "link", "set", "lo", "up")
        ns_command(trans, "ip", "link", "add", "out0", "type", "veth", "peer", "name", "ep0")
        command("ip", "-n", trans, "link", "set", "ep0", "netns", recv)
        for ns, dev, a4, a6 in ((trans, "out0", "10.23.0.1/24", "fd23::1/64"),
                                (recv, "ep0", "10.23.0.2/24", "fd23::2/64")):
            command("ip", "-n", ns, "link", "set", dev, "mtu", mtu, "up")
            command("ip", "-n", ns, "addr", "add", a4, "dev", dev)
            command("ip", "-n", ns, "-6", "addr", "add", a6, "dev", dev, "nodad")
        ns_command(trans, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1",
                   "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
        command("ip", "-n", recv, "route", "add", "default", "via", "10.23.0.1", "dev", "ep0")
        # Input comes from a local UDP_SEGMENT socket directly to TUN. Only the
        # translated output link is forced to segment/complete before capture.
        ns_command(trans, "ethtool", "-K", "out0", "tx", "off", "gso", "off", "tso", "off")
        ns_command(recv, "ethtool", "-K", "ep0", "gro", "off", "lro", "off")
        (group / "output-features.txt").write_text(ns_command(trans, "ethtool", "-k", "out0").stdout)
        cfg = group / "tayga.conf"
        cfg.write_text(f"tun-device usotun\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8:64::1\n"
                       f"prefix 64:ff9b::/96\nwkpf-strict no\nmap {ADDR4} {ADDR6}\n"
                       f"workers {workers}\ntun-offload {mode}\nofflink-mtu {mtu}\n")
        if args.steering == "groups" or args.dispatch == "flows":
            # Fresh disposable TUN is mandatory for the experimental policy.
            # Configure the test MTU/routes after negotiation; offlink-mtu is
            # already fixed in the daemon configuration before startup.
            daemon = subprocess.Popen(["ip", "netns", "exec", trans, args.binary, "-d", "-c", str(cfg), "--tun-steering="+args.steering,"--dispatch="+args.dispatch,"--packet-io="+args.packet_io],
                                      stdout=log_fd, stderr=log_fd)
            for _ in range(100):
                if ("Packet I/O: dispatch="+args.dispatch+" transmit="+args.packet_io in log.read_text()
                        and (args.steering != "groups" or "TUN steering requested=groups effective=groups" in log.read_text())): break
                assert daemon.poll() is None, log.read_text()
                time.sleep(.05)
            else: raise AssertionError("experimental steering not activated")
        else:
            ns_command(trans, args.binary, "-c", cfg, "--mktun")
        command("ip", "-n", trans, "link", "set", "usotun", "mtu", mtu, "up")
        if direction == "upload":
            source_in, dest_in, family_in = ADDR4, PEER4, 4
            source_out, dest_out, family_out = ADDR6, PEER6, 6
            command("ip", "-n", trans, "addr", "add", ADDR4 + "/32", "dev", "lo")
            command("ip", "-n", trans, "route", "add", PEER4 + "/32", "dev", "usotun")
            command("ip", "-n", trans, "-6", "route", "add", PEER6 + "/128", "via", "fd23::2", "dev", "out0")
            command("ip", "-n", recv, "-6", "addr", "add", PEER6 + "/128", "dev", "lo", "nodad")
        else:
            source_in, dest_in, family_in = PEER6, ADDR6, 6
            source_out, dest_out, family_out = PEER4, ADDR4, 4
            command("ip", "-n", trans, "-6", "addr", "add", PEER6 + "/128", "dev", "lo", "nodad")
            command("ip", "-n", trans, "-6", "route", "add", ADDR6 + "/128", "dev", "usotun")
            command("ip", "-n", trans, "route", "add", ADDR4 + "/32", "via", "10.23.0.2", "dev", "out0")
            command("ip", "-n", recv, "addr", "add", ADDR4 + "/32", "dev", "lo")
        if daemon is None:
            daemon = subprocess.Popen(["ip", "netns", "exec", trans, args.binary, "-d", "-c", str(cfg),"--packet-io="+args.packet_io],
                                      stdout=log_fd, stderr=log_fd)
        time.sleep(0.15)
        assert daemon.poll() is None, log.read_text()
        before = {}
        results = []
        cases = [("plain-0", [0], False), ("plain-1", [1], False), ("one-segment", [64], True)]
        for size in (1, 3, 64, 256, 512, 1200):
            cases.append((f"exact-{size}", [size] * 4, True))
        cases += [("small-tail", [1200, 1200, 17], True), ("max-segments", [64] * 128, True)]
        if mtu == 1500:
            cases += [("boundary-1260", [1232] * 4, True), ("boundary-1261", [1233] * 4, True),
                      ("mixed-df-tail", [1233, 1233, 17], True)]
        for name, lengths, segmented in cases:
            case = group / name
            case.mkdir()
            receiver_spec = {"lengths": lengths, "family": family_out, "source": source_out,
                             "destination": dest_out, "output": str(case / "receiver.json"), "pcap": str(case / "wire.pcap")}
            sender_spec = {"lengths": lengths, "family": family_in, "source": source_in,
                           "destination": dest_in, "segmented": segmented}
            (case / "receiver-spec.json").write_text(json.dumps(receiver_spec))
            (case / "sender-spec.json").write_text(json.dumps(sender_spec))
            receiver = subprocess.Popen(["ip", "netns", "exec", recv, sys.executable, __file__,
                                         "receive", str(case / "receiver-spec.json")],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([receiver.stdout], [], [], 3)
                assert ready and receiver.stdout.readline().strip() == "READY", "receiver not ready"
                sent = ns_command(trans, sys.executable, __file__, "send", str(case / "sender-spec.json"))
                (case / "sender.json").write_text(sent.stdout)
                _, errors = receiver.communicate(timeout=6)
                assert receiver.returncode == 0, errors
            finally:
                if receiver.poll() is None:
                    receiver.kill()
                    receiver.communicate()
            if mode != "off":
                daemon.send_signal(signal.SIGUSR2)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    after = gso_stats(log)
                    aggregate_expected = mode in ("udp", "auto") and segmented and len(lengths) > 1
                    if after and (after.get("udp_rx_aggregates", 0) > before.get("udp_rx_aggregates", 0)
                                  if aggregate_expected else True):
                        break
                    time.sleep(0.05)
                    # Worker counters publish on their interval; refresh the log
                    # snapshot rather than re-reading a pre-publication line.
                    daemon.send_signal(signal.SIGUSR2)
                delta = {k: v - before.get(k, 0) for k, v in after.items()}
                before = after
            else:
                delta = {}
            aggregate_expected = mode in ("udp", "auto") and segmented and len(lengths) > 1
            if aggregate_expected:
                assert delta.get("udp_rx_aggregates", 0) > 0, ("UDP_SEGMENT never reached TAYGA", name, delta, log.read_text())
                mixed_df = any(n + 28 <= 1260 for n in lengths) and any(n + 28 > 1260 for n in lengths)
                if direction == "download" and mixed_df:
                    assert delta.get("udp_sw_segments") == len(lengths), (name, delta)
                else:
                    assert delta.get("udp_tx_aggregates", 0) > 0, (name, delta)
                    assert delta.get("udp_sw_segments", 0) == 0, (name, delta)
            result = {"case": name, "mode": mode, "direction": direction, "workers": workers, "mtu": mtu,
                      "lengths": lengths, "aggregate_expected": aggregate_expected, "gso_delta": delta,
                      "receiver": json.loads((case / "receiver.json").read_text())}
            (case / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            results.append(result)
            print(f"PASS {mode} workers={workers} mtu={mtu} {direction} {name}: aggregates={delta.get('udp_rx_aggregates', 0)}", flush=True)
        return results
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
        log_fd.close()
        for ns in (recv, trans):
            command("ip", "netns", "del", ns, check=False)


def main():
    if len(sys.argv) == 3 and sys.argv[1] in ("send", "receive"):
        endpoint(sys.argv[1], sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="/usr/sbin/tayga")
    parser.add_argument("--dispatch",choices=("kernel","flows"),default="kernel")
    parser.add_argument("--packet-io",choices=("sync","uring"),default="sync")
    parser.add_argument("--steering", choices=("kernel", "groups"), default="kernel")
    parser.add_argument("--output", required=True)
    parser.add_argument("--modes", nargs="+", choices=("off", "tcp", "auto", "udp"), default=["udp"])
    parser.add_argument("--workers", nargs="+", type=int, default=[0, 3])
    parser.add_argument("--mtus", nargs="+", type=int, default=[1280, 1500])
    args = parser.parse_args()
    assert sys.platform.startswith("linux") and os.geteuid() == 0, "requires Linux root"
    # Hold through setup, capture and cleanup. Other harnesses must use this
    # same lock before sharing the guest with this test.
    run_lock = os.fdopen(os.open("/tmp/tayga-perf-workflow.lock", os.O_RDONLY | os.O_CREAT, 0o644), "r")
    fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    args.binary = str(Path(args.binary).resolve())
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / 'test-runner.py').write_bytes(Path(__file__).read_bytes())
    (root / 'settings.json').write_text(json.dumps(vars(args), indent=2))
    binary_hash = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
    results = []
    try:
        for mode in args.modes:
            for workers in args.workers:
                for mtu in args.mtus:
                    for direction in ("upload", "download"):
                        results.extend(run_group(args, mode, workers, mtu, direction, root))
    finally:
        # Include cases completed before a later case in the same group failed.
        results = [json.loads(p.read_text()) for p in sorted(root.glob("*/*/result.json"))]
        (root / "summary.json").write_text(json.dumps({"binary": args.binary, "binary_sha256": binary_hash, "steering": args.steering,"dispatch":args.dispatch,"packet_io":args.packet_io,
                    "kernel": command("uname", "-a").stdout.strip(), "completed_cases": len(results),
                    "results": results}, indent=2) + "\n")
    print(f"All {len(results)} kernel UDP cases passed. Artifacts: {root}")


if __name__ == "__main__":
    main()
