#
#   part of TAYGA test suite
#   test/integration/protocols.py - Extended Network Protocols Compatibility Tests
#   Ref: improvenments/network-protocols-compatibility-and-testing-guide.md
#   RFC 7915, RFC 4960 (SCTP), RFC 8684 (MPTCP), RFC 9000 (QUIC),
#   RFC 2784 (GRE), RFC 4303 (ESP), RFC 3948 (NAT-T), RFC 7348 (VXLAN),
#   RFC 8926 (GENEVE), RFC 8200 §4.7 (No Next Header), RFC 5389 (STUN)
#

import struct
import time
from random import randbytes
from test_env import (
    test_env,
    test_result,
    router,
)
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.layers.inet6 import IPv6ExtHdrHopByHop

# Initialize test environment for protocols integration suite
test = test_env("test/protocols")

# SCTP CRC32c lookup table (polynomial 0x1EDC6F41, RFC 4960 / RFC 3309)
CRC32C_TABLE = [
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
    0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
    0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
    0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
    0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
    0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
    0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
    0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
    0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
    0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
    0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAD24, 0x42752E27,
    0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
    0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
    0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
    0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
    0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
    0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
    0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
    0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
    0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
    0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
    0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
    0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
    0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
    0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
    0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
    0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
    0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
    0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
    0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
    0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
    0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
    0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
]


def sctp_crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    crc ^= 0xFFFFFFFF
    return struct.unpack("<I", struct.pack(">I", crc))[0]


def build_sctp_packet(sport: int, dport: int, tag: int, chunks: bytes) -> bytes:
    hdr_no_cksum = struct.pack("!HHII", sport, dport, tag, 0)
    cksum = sctp_crc32c(hdr_no_cksum + chunks)
    return struct.pack("!HHI", sport, dport, tag) + struct.pack("<I", cksum) + chunks


# Shared validator expectations
expect_sa = ""
expect_da = ""
expect_nh = 0
expect_payload = None
expect_csum = -1
expect_flags = None
expect_id = -1
expect_type = 0
expect_code = 0
expect_mtu = -1


def proto_ip6_val(pkt):
    res = test_result()
    res.check("Contains IPv6", pkt.haslayer(IPv6))
    if not pkt.haslayer(IPv6):
        return res
    res.compare("Src", pkt[IPv6].src, str(expect_sa))
    res.compare("Dest", pkt[IPv6].dst, str(expect_da))
    res.compare("NH", pkt[IPv6].nh, expect_nh)
    if expect_payload is not None:
        raw_load = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else bytes(pkt[IPv6].payload)
        res.compare("Payload", raw_load, expect_payload)
    if expect_csum >= 0:
        if pkt.haslayer(TCP):
            res.compare("Checksum TCP", pkt[TCP].chksum, expect_csum)
        elif pkt.haslayer(UDP):
            res.compare("Checksum UDP", pkt[UDP].chksum, expect_csum)
    return res


def proto_ip4_val(pkt):
    res = test_result()
    res.check("Contains IPv4", pkt.haslayer(IP))
    if not pkt.haslayer(IP):
        return res
    res.compare("Src", pkt[IP].src, str(expect_sa))
    res.compare("Dest", pkt[IP].dst, str(expect_da))
    res.compare("Proto", pkt[IP].proto, expect_nh)
    if expect_flags is not None:
        res.compare("Flags", pkt[IP].flags, expect_flags)
    if expect_id == 0:
        res.compare("ID", pkt[IP].id, 0)
    elif expect_id == 1:
        res.check("ID Nonzero", pkt[IP].id != 0)
    if expect_payload is not None:
        raw_load = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else bytes(pkt[IP].payload)
        res.compare("Payload", raw_load, expect_payload)
    if expect_csum >= 0:
        if pkt.haslayer(TCP):
            res.compare("Checksum TCP", pkt[TCP].chksum, expect_csum)
        elif pkt.haslayer(UDP):
            res.compare("Checksum UDP", pkt[UDP].chksum, expect_csum)
    return res


def icmp4_ptb_val(pkt):
    res = test_result()
    res.check("Contains IP", pkt.haslayer(IP))
    res.check("Contains ICMP", pkt.haslayer(ICMP))
    if not pkt.haslayer(IP) or not pkt.haslayer(ICMP):
        return res
    res.compare("Src", pkt[IP].src, str(expect_sa))
    res.compare("Dest", pkt[IP].dst, str(expect_da))
    res.compare("Type", pkt[ICMP].type, expect_type)
    res.compare("Code", pkt[ICMP].code, expect_code)
    if expect_mtu >= 0:
        res.compare("NextHop MTU", pkt[ICMP].nexthopmtu, expect_mtu)
    return res


# ============================================================================
# Section 1: SCTP (IPPROTO_SCTP = 132) Stateless Translation & CRC32c Integrity
# ============================================================================
def sec_l4_sctp():
    global expect_sa, expect_da, expect_nh, expect_payload, expect_csum
    test.tayga_conf.default()
    test.reload()

    # 1. SCTP 4->6 INIT Chunk
    # Chunk: Type=1 (INIT), Flags=0, Length=20, InitTag=0x11223344, a_rwnd=32768, OS=10, MIS=10, InitTSN=1
    init_chunk = struct.pack("!BBHIIHHI", 1, 0, 20, 0x11223344, 32768, 10, 10, 1)
    sctp_bytes = build_sctp_packet(5000, 5000, 0, init_chunk)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 132
    expect_payload = sctp_bytes
    expect_csum = -1
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=132) / Raw(sctp_bytes)
    test.send_and_check(pkt4, proto_ip6_val, "SCTP 4->6 INIT Chunk")

    # 2. SCTP 6->4 INIT Chunk
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 132
    expect_payload = sctp_bytes
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=132) / Raw(sctp_bytes)
    test.send_and_check(pkt6, proto_ip4_val, "SCTP 6->4 INIT Chunk")

    # 3. SCTP 4->6 DATA Chunk
    # Chunk: Type=0 (DATA), Flags=3 (UB), Length=16+len, TSN=100, StreamID=1, SSN=1, PPID=0
    payload_data = b"Tayga SCTP Stream Transfer Verification"
    pad_len = (4 - (len(payload_data) % 4)) % 4
    data_chunk = struct.pack("!BBHIIII", 0, 3, 16 + len(payload_data), 100, 1, 1, 0) + payload_data + (b"\x00" * pad_len)
    sctp_data_bytes = build_sctp_packet(5001, 5001, 0x11223344, data_chunk)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 132
    expect_payload = sctp_data_bytes
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=132) / Raw(sctp_data_bytes)
    test.send_and_check(pkt4, proto_ip6_val, "SCTP 4->6 DATA Chunk")

    # 4. SCTP 6->4 DATA Chunk
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 132
    expect_payload = sctp_data_bytes
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=132) / Raw(sctp_data_bytes)
    test.send_and_check(pkt6, proto_ip4_val, "SCTP 6->4 DATA Chunk")

    test.section("Layer 4: SCTP Transport Compatibility")


# ============================================================================
# Section 2: DCCP (33) & UDP-Lite (136) Payload Pass-Through
# ============================================================================
def sec_l4_udplite_dccp():
    global expect_sa, expect_da, expect_nh, expect_payload, expect_csum
    test.tayga_conf.default()
    test.reload()

    # 1. UDP-Lite (136) 4->6
    # UDP-Lite Header: sport(2), dport(2), cov(2, min 8), csum(2)
    raw_udplite = struct.pack("!HHHH", 50000, 50001, 8, 0x1234) + randbytes(64)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 136
    expect_payload = raw_udplite
    expect_csum = -1
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=136) / Raw(raw_udplite)
    test.send_and_check(pkt4, proto_ip6_val, "UDP-Lite 4->6 Payload Pass")

    # 2. UDP-Lite (136) 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 136
    expect_payload = raw_udplite
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=136) / Raw(raw_udplite)
    test.send_and_check(pkt6, proto_ip4_val, "UDP-Lite 6->4 Payload Pass")

    # 3. DCCP (33) 4->6
    # DCCP Generic Header: sport(2), dport(2), data_offset(1), ccval_cscov(1), csum(2)
    raw_dccp = struct.pack("!BBBBH", 0x1F, 0x90, 0x1F, 0x91, 0x04) + struct.pack("!BB", 0x00, 0x00) + randbytes(64)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 33
    expect_payload = raw_dccp
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=33) / Raw(raw_dccp)
    test.send_and_check(pkt4, proto_ip6_val, "DCCP 4->6 Payload Pass")

    # 4. DCCP (33) 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 33
    expect_payload = raw_dccp
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=33) / Raw(raw_dccp)
    test.send_and_check(pkt6, proto_ip4_val, "DCCP 6->4 Payload Pass")

    test.section("Layer 4: UDP-Lite & DCCP Transport Diagnostics")


# ============================================================================
# Section 3: Multipath TCP (Option 30) & Extended 40-Byte TCP Options
# ============================================================================
def sec_l4_mptcp_extended_tcp():
    global expect_sa, expect_da, expect_nh, expect_payload, expect_csum, expect_flags, expect_id
    test.tayga_conf.default()
    test.reload()

    # MPTCP MP_CAPABLE SYN Options:
    # MSS (4B) + Timestamp (10B) + SAckOK (2B) + MP_CAPABLE (12B) + NOP (1B) + NOP (1B) + End (10B padding to 40B)
    mp_capable_data = b"\x00\x10\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"  # Subtype 0 (MP_CAPABLE), flags, sender key
    tcp_opts_40b = [
        ('MSS', 1400),
        ('Timestamp', (0x12345678, 0)),
        ('SAckOK', b''),
        (30, mp_capable_data),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
        ('NOP', None),
    ]

    # 1. MPTCP MP_CAPABLE 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 6
    expect_payload = None
    expect_csum = -1
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / TCP(
        sport=12345, dport=80, flags="S", seq=1000, options=tcp_opts_40b
    )
    test.send_and_check(pkt4, proto_ip6_val, "MPTCP MP_CAPABLE 4->6 40B Options")

    # 2. MPTCP MP_CAPABLE 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 6
    expect_flags = "DF"
    expect_id = 0
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / TCP(
        sport=12345, dport=80, flags="S", seq=1000, options=tcp_opts_40b
    )
    test.send_and_check(pkt6, proto_ip4_val, "MPTCP MP_CAPABLE 6->4 40B Options")
    expect_flags = None
    expect_id = -1

    # 3. MPTCP MP_JOIN (Option 30 subtype 1) 4->6
    mp_join_data = b"\x10\x00\xaa\xbb\xcc\xdd\x11\x22\x33\x44\x01\x00"  # Subtype 1 (MP_JOIN), receiver token, sender nonce
    tcp_opts_join = [
        ('MSS', 1400),
        ('Timestamp', (0x12345678, 0x87654321)),
        (30, mp_join_data),
        ('NOP', None),
        ('NOP', None),
    ]
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 6
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / TCP(
        sport=12346, dport=80, flags="SA", seq=2000, ack=1001, options=tcp_opts_join
    )
    test.send_and_check(pkt4, proto_ip6_val, "MPTCP MP_JOIN 4->6 Extended Options")

    # 4. MPTCP MP_JOIN 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 6
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / TCP(
        sport=12346, dport=80, flags="SA", seq=2000, ack=1001, options=tcp_opts_join
    )
    test.send_and_check(pkt6, proto_ip4_val, "MPTCP MP_JOIN 6->4 Extended Options")

    test.section("Layer 4: MPTCP & Extended TCP Options")


# ============================================================================
# Section 4: QUIC Transport & PMTU Sizing (RFC 9000 & RFC 7915 §5.1)
# ============================================================================
def sec_l4_quic():
    global expect_sa, expect_da, expect_nh, expect_payload, expect_flags, expect_id
    global expect_type, expect_code, expect_mtu
    test.tayga_conf.default()
    test.reload()

    # 1. QUIC Initial 6->4 Sizing: 1200B UDP payload
    # IPv6 plen = 1208 -> IPv4 total len = 1228 <= 1260 -> DF=0, non-zero ID
    quic_initial_payload = randbytes(1200)
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_flags = 0
    expect_id = 1  # non-zero ID
    expect_payload = None
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=443, dport=443) / Raw(quic_initial_payload)
    test.send_and_check(pkt6, proto_ip4_val, "QUIC Initial 6->4 Sizing (1200B)")

    # 2. QUIC DPLPMTUD 6->4 Sizing: 1350B UDP payload
    # IPv6 plen = 1358 -> IPv4 total len = 1378 > 1260 -> DF=1, ID = 0
    quic_probe_payload = randbytes(1350)
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_flags = "DF"
    expect_id = 0  # atomic zero ID
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=443, dport=443) / Raw(quic_probe_payload)
    test.send_and_check(pkt6, proto_ip4_val, "QUIC DPLPMTUD 6->4 Sizing (1350B)")
    expect_flags = None
    expect_id = -1

    # 3. QUIC 4->6 DF=1 Exceed MTU PTB Generation
    # Sending 1472B UDP payload with DF=1 (IPv4 len = 1500; translated IPv6 would be 1520 > MTU 1500)
    # TAYGA must reply with ICMPv4 Type 3 Code 4 (Next-Hop MTU = 1480)
    expect_sa = str(test.tayga_ipv4)
    expect_da = str(test.public_ipv4)
    expect_type = 3
    expect_code = 4
    expect_mtu = 1480
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), flags="DF", len=1500) / UDP(sport=443, dport=443, len=1480) / Raw(randbytes(1472))
    test.send_and_check(pkt4, icmp4_ptb_val, "QUIC 4->6 DF=1 Exceed MTU PTB")
    expect_mtu = -1

    test.section("Layer 4: QUIC Transport & PMTU Convergence")


# ============================================================================
# Section 5: Generic Routing Encapsulation (GRE, Proto 47, RFC 2784)
# ============================================================================
def sec_l4_gre():
    global expect_sa, expect_da, expect_nh, expect_payload
    test.tayga_conf.default()
    test.reload()

    # GRE framing without checksum: Flags=0 (2B), Proto=0x0800 (IPv4)
    inner_pkt = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0, id=1, seq=1) / Raw(b"gre-tunnel-payload"))
    gre_no_csum = struct.pack("!HH", 0x0000, 0x0800) + inner_pkt

    # 1. GRE 4->6 Without Checksum (C=0)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 47
    expect_payload = gre_no_csum
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=47) / Raw(gre_no_csum)
    test.send_and_check(pkt4, proto_ip6_val, "GRE 4->6 Without Checksum (C=0)")

    # 2. GRE 6->4 Without Checksum (C=0)
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 47
    expect_payload = gre_no_csum
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=47) / Raw(gre_no_csum)
    test.send_and_check(pkt6, proto_ip4_val, "GRE 6->4 Without Checksum (C=0)")

    # GRE framing with checksum: Flags=0x8000 (C=1), Proto=0x0800, Checksum=0x1234, Reserved=0x0000
    gre_with_csum = struct.pack("!HHHH", 0x8000, 0x0800, 0x1234, 0x0000) + inner_pkt

    # 3. GRE 4->6 With Checksum (C=1)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 47
    expect_payload = gre_with_csum
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=47) / Raw(gre_with_csum)
    test.send_and_check(pkt4, proto_ip6_val, "GRE 4->6 With Checksum (C=1)")

    # 4. GRE 6->4 With Checksum (C=1)
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 47
    expect_payload = gre_with_csum
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=47) / Raw(gre_with_csum)
    test.send_and_check(pkt6, proto_ip4_val, "GRE 6->4 With Checksum (C=1)")

    test.section("Tunneling: GRE Encapsulation (RFC 2784)")


# ============================================================================
# Section 6: IPsec ESP (50) & NAT-T (UDP 4500)
# ============================================================================
def sec_tunneling_ipsec_esp_natt():
    global expect_sa, expect_da, expect_nh, expect_payload
    test.tayga_conf.default()
    test.reload()

    # Native ESP Tunnel Mode payload: SPI=0xDEADBEEF (4B), Seq=1 (4B), IV/Ciphertext (32B), ICV (16B)
    esp_raw = struct.pack("!II", 0xDEADBEEF, 1) + randbytes(32) + randbytes(16)

    # 1. IPsec Native ESP 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 50
    expect_payload = esp_raw
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=50) / Raw(esp_raw)
    test.send_and_check(pkt4, proto_ip6_val, "IPsec Native ESP 4->6 Tunnel Mode")

    # 2. IPsec Native ESP 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 50
    expect_payload = esp_raw
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=50) / Raw(esp_raw)
    test.send_and_check(pkt6, proto_ip4_val, "IPsec Native ESP 6->4 Tunnel Mode")

    # IPsec NAT-T UDP 4500 with Non-ESP Marker (4 zero bytes) + IKE payload
    ike_payload = struct.pack("!II", 0x11223344, 0x55667788) + randbytes(40)
    natt_ike = b"\x00\x00\x00\x00" + ike_payload

    # 3. IPsec NAT-T UDP 4500 Non-ESP Marker 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = natt_ike
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=4500, dport=4500) / Raw(natt_ike)
    test.send_and_check(pkt4, proto_ip6_val, "IPsec NAT-T UDP 4500 Non-ESP Marker 4->6")

    # 4. IPsec NAT-T UDP 4500 Non-ESP Marker 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = natt_ike
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=4500, dport=4500) / Raw(natt_ike)
    test.send_and_check(pkt6, proto_ip4_val, "IPsec NAT-T UDP 4500 Non-ESP Marker 6->4")

    # IPsec NAT-T UDP 4500 with ESP Packet (non-zero SPI at start)
    natt_esp = esp_raw

    # 5. IPsec NAT-T UDP 4500 ESP Packet 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = natt_esp
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=4500, dport=4500) / Raw(natt_esp)
    test.send_and_check(pkt4, proto_ip6_val, "IPsec NAT-T UDP 4500 ESP Packet 4->6")

    # 6. IPsec NAT-T UDP 4500 ESP Packet 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = natt_esp
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=4500, dport=4500) / Raw(natt_esp)
    test.send_and_check(pkt6, proto_ip4_val, "IPsec NAT-T UDP 4500 ESP Packet 6->4")

    test.section("Tunneling: IPsec ESP & NAT-T (RFC 4303 / RFC 3948)")


# ============================================================================
# Section 7: VXLAN (4789) & GENEVE (6081) UDP Overlay Tunnels
# ============================================================================
def sec_tunneling_vxlan_geneve():
    global expect_sa, expect_da, expect_nh, expect_payload
    # Configure udp-cksum-mode calc so zero checksum IPv4 packets get computed on IPv6
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "calc"
    test.reload()

    # VXLAN Header: Flags=0x08000000 (VNI valid), VNI=100 (24-bit), Reserved=0
    # Followed by inner Ethernet + IP + ICMP frame
    vxlan_hdr = struct.pack("!II", 0x08000000, 100 << 8)
    inner_frame = randbytes(64)
    vxlan_datagram = vxlan_hdr + inner_frame

    # 1. VXLAN 4->6 Zero Checksum with calc mode
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = vxlan_datagram
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=54321, dport=4789, chksum=0) / Raw(vxlan_datagram)
    test.send_and_check(pkt4, proto_ip6_val, "VXLAN 4->6 Zero Checksum Calc Mode")

    # 2. VXLAN 6->4 Tunnel Forward
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = vxlan_datagram
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=54321, dport=4789) / Raw(vxlan_datagram)
    test.send_and_check(pkt6, proto_ip4_val, "VXLAN 6->4 Tunnel Forward")

    # GENEVE Header: Ver=0, OptLen=0, OAM=0, Crit=0, Rsvd=0, ProtoType=0x6558 (Trans Ether Bridging), VNI=200
    geneve_hdr = struct.pack("!HHII", 0x0000, 0x6558, 200 << 8, 0)
    geneve_datagram = geneve_hdr + inner_frame

    # 3. GENEVE 4->6 Tunnel Datagram
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = geneve_datagram
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=54322, dport=6081) / Raw(geneve_datagram)
    test.send_and_check(pkt4, proto_ip6_val, "GENEVE 4->6 Tunnel Datagram")

    # 4. GENEVE 6->4 Tunnel Datagram
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = geneve_datagram
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=54322, dport=6081) / Raw(geneve_datagram)
    test.send_and_check(pkt6, proto_ip4_val, "GENEVE 6->4 Tunnel Datagram")

    # 5. VXLAN 4->6 with udp-cksum-mode drop -> verify silent drop
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "drop"
    test.reload()
    pkt4_zero = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=54321, dport=4789, chksum=0) / Raw(vxlan_datagram)
    test.send_and_none(pkt4_zero, "VXLAN 4->6 Zero Checksum Drop Mode")

    test.section("Tunneling: VXLAN & GENEVE (RFC 7348 / RFC 8926)")


# ============================================================================
# Section 8: IP Encap (Proto 4 & 41) & WireGuard (UDP 51820)
# ============================================================================
def sec_tunneling_ip_encap():
    global expect_sa, expect_da, expect_nh, expect_payload
    test.tayga_conf.default()
    test.reload()

    # Inner IPv4 packet for IP-in-IP
    inner_ip4 = bytes(IP(src="10.1.1.1", dst="10.2.2.2") / ICMP(type=8, code=0) / Raw(b"inner-ip4-packet"))

    # 1. IP-in-IP 4->6 (Proto 4)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 4
    expect_payload = inner_ip4
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=4) / Raw(inner_ip4)
    test.send_and_check(pkt4, proto_ip6_val, "IP-in-IP 4->6 (Proto 4)")

    # 2. IP-in-IP 6->4 (Proto 4)
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 4
    expect_payload = inner_ip4
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=4) / Raw(inner_ip4)
    test.send_and_check(pkt6, proto_ip4_val, "IP-in-IP 6->4 (Proto 4)")

    # Inner IPv6 packet for 6in4 / SIT (Proto 41)
    inner_ip6 = bytes(IPv6(src="2001:db8:ffff::1", dst="2001:db8:ffff::2") / ICMP(type=8, code=0) / Raw(b"inner-ip6-packet"))

    # 3. 6in4 / SIT 4->6 (Proto 41)
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 41
    expect_payload = inner_ip6
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=41) / Raw(inner_ip6)
    test.send_and_check(pkt4, proto_ip6_val, "6in4 / SIT 4->6 (Proto 41)")

    # 4. 6in4 / SIT 6->4 (Proto 41)
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 41
    expect_payload = inner_ip6
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=41) / Raw(inner_ip6)
    test.send_and_check(pkt6, proto_ip4_val, "6in4 / SIT 6->4 (Proto 41)")

    # WireGuard Messages:
    # Type 1: Initiation (148 bytes) -> Type(1), Reserved(3B), SenderIndex(4B), UnencryptedEphemeral(32B), EncryptedStatic(48B), EncryptedTimestamp(28B), MAC1(16B), MAC2(16B)
    wg_init = struct.pack("<I", 1) + struct.pack("<I", 0x12345678) + randbytes(140)
    assert len(wg_init) == 148

    # 5. WireGuard Type 1 Initiation 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = wg_init
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=51820, dport=51820) / Raw(wg_init)
    test.send_and_check(pkt4, proto_ip6_val, "WireGuard Type 1 Initiation 4->6")

    # 6. WireGuard Type 1 Initiation 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = wg_init
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=51820, dport=51820) / Raw(wg_init)
    test.send_and_check(pkt6, proto_ip4_val, "WireGuard Type 1 Initiation 6->4")

    # Type 2: Response (92 bytes) -> Type(2), Reserved(3B), SenderIndex(4B), ReceiverIndex(4B), UnencryptedEphemeral(32B), EncryptedEmpty(16B), MAC1(16B), MAC2(16B)
    wg_resp = struct.pack("<I", 2) + struct.pack("<II", 0x1111, 0x2222) + randbytes(80)
    assert len(wg_resp) == 92

    # 7. WireGuard Type 2 Response 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = wg_resp
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=51820, dport=51820) / Raw(wg_resp)
    test.send_and_check(pkt4, proto_ip6_val, "WireGuard Type 2 Response 4->6")

    # 8. WireGuard Type 2 Response 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = wg_resp
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=51820, dport=51820) / Raw(wg_resp)
    test.send_and_check(pkt6, proto_ip4_val, "WireGuard Type 2 Response 6->4")

    # Type 4: Data (Header 16 bytes + payload + auth tag 16 bytes)
    wg_data = struct.pack("<IIQ", 4, 0x2222, 1) + randbytes(64) + randbytes(16)

    # 9. WireGuard Type 4 Data 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = wg_data
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=51820, dport=51820) / Raw(wg_data)
    test.send_and_check(pkt4, proto_ip6_val, "WireGuard Type 4 Data 4->6")

    # 10. WireGuard Type 4 Data 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = wg_data
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=51820, dport=51820) / Raw(wg_data)
    test.send_and_check(pkt6, proto_ip4_val, "WireGuard Type 4 Data 6->4")

    test.section("Tunneling: IP Encap & WireGuard Protocols")


# ============================================================================
# Section 9: Layer 3 Protocol 59 (No Next Header) & Header Edge Cases
# ============================================================================
def sec_l3_edge_cases():
    global expect_sa, expect_da, expect_nh, expect_payload
    test.tayga_conf.default()
    test.reload()

    # 1. IPv6 No Next Header (Proto 59, plen=0)
    # RFC 8200 §4.7: Next Header 59 indicates nothing follows.
    # TAYGA emits an IPv4 packet with total length = 20, proto = 59, 0 payload bytes.
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 59
    expect_payload = b""
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=59, plen=0)
    test.send_and_check(pkt6, proto_ip4_val, "IPv6 No Next Header (Proto 59, plen=0)")

    # 2. IPv6 Hop-by-Hop + Proto 59
    # TAYGA strips Hop-by-Hop and sets IPv4 proto = 59, total len = 20.
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 59
    expect_payload = b""
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=0) / IPv6ExtHdrHopByHop(nh=59)
    test.send_and_check(pkt6, proto_ip4_val, "IPv6 Hop-by-Hop + Proto 59")

    # 3. IPv6 Proto 59 With Raw Payload
    raw_59 = randbytes(32)
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 59
    expect_payload = raw_59
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate), nh=59) / Raw(raw_59)
    test.send_and_check(pkt6, proto_ip4_val, "IPv6 Proto 59 With Raw Payload")

    # 4. IPv4 Proto 59 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 59
    expect_payload = raw_59
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate), proto=59) / Raw(raw_59)
    test.send_and_check(pkt4, proto_ip6_val, "IPv4 Proto 59 4->6")

    test.section("Layer 3: Protocol 59 & Header Edge Cases")


# ============================================================================
# Section 10: Layer 7 Application Protocols Over UDP & TCP
# ============================================================================
def sec_l7_application_patterns():
    global expect_sa, expect_da, expect_nh, expect_payload
    test.tayga_conf.default()
    test.reload()

    # STUN Binding Request (RFC 5389):
    # MsgType=0x0001 (2B), MsgLen=0 (2B), MagicCookie=0x2112A442 (4B), TransID=12B
    stun_req = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + randbytes(12)

    # 1. STUN RFC 5389 Binding Request 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = stun_req
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=50000, dport=3478) / Raw(stun_req)
    test.send_and_check(pkt4, proto_ip6_val, "STUN RFC 5389 Binding Request 4->6")

    # 2. STUN RFC 5389 Binding Request 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = stun_req
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=50000, dport=3478) / Raw(stun_req)
    test.send_and_check(pkt6, proto_ip4_val, "STUN RFC 5389 Binding Request 6->4")

    # STUN Binding Response with XOR-MAPPED-ADDRESS:
    # Attr Type=0x0020, Len=8, Rsvd=0, Family=1 (IPv4), X-Port, X-Address
    attr_xor_addr = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, 50000 ^ (0x2112A442 >> 16), 0xC0000201 ^ 0x2112A442)
    stun_resp = struct.pack("!HHI", 0x0101, len(attr_xor_addr), 0x2112A442) + randbytes(12) + attr_xor_addr

    # 3. STUN RFC 5389 Binding Response 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = stun_resp
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=3478, dport=50000) / Raw(stun_resp)
    test.send_and_check(pkt4, proto_ip6_val, "STUN RFC 5389 Binding Response 4->6")

    # 4. STUN RFC 5389 Binding Response 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = stun_resp
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=3478, dport=50000) / Raw(stun_resp)
    test.send_and_check(pkt6, proto_ip4_val, "STUN RFC 5389 Binding Response 6->4")

    # DNS over UDP with EDNS0 (UDP 53)
    # Header (12B) + QNAME ("example.com", Type A, Class IN) + OPT RR (Type 41, UDP Size 4096)
    dns_query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1) + b"\x07example\x03com\x00\x00\x01\x00\x01" + b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"

    # 5. DNS over UDP 4->6 with EDNS0
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = dns_query
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=53000, dport=53) / Raw(dns_query)
    test.send_and_check(pkt4, proto_ip6_val, "DNS over UDP 4->6 with EDNS0")

    # 6. DNS over UDP 6->4 with EDNS0
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = dns_query
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=53000, dport=53) / Raw(dns_query)
    test.send_and_check(pkt6, proto_ip4_val, "DNS over UDP 6->4 with EDNS0")

    # DNS over TCP (Port 53): 2-byte length prefix + DNS query
    dns_tcp_msg = struct.pack("!H", len(dns_query)) + dns_query

    # 7. DNS over TCP 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 6
    expect_payload = dns_tcp_msg
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / TCP(sport=53001, dport=53, flags="PA", seq=100) / Raw(dns_tcp_msg)
    test.send_and_check(pkt4, proto_ip6_val, "DNS over TCP 4->6 (Port 53)")

    # 8. DNS over TCP 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 6
    expect_payload = dns_tcp_msg
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / TCP(sport=53001, dport=53, flags="PA", seq=100) / Raw(dns_tcp_msg)
    test.send_and_check(pkt6, proto_ip4_val, "DNS over TCP 6->4 (Port 53)")

    # Passive FTP Control (Port 21): PASV response containing IPv4 literal
    ftp_pasv_line = b"227 Entering Passive Mode (198,51,100,10,195,80)\r\n"

    # 9. Passive FTP PASV Response 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 6
    expect_payload = ftp_pasv_line
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / TCP(sport=21, dport=54000, flags="PA", seq=200) / Raw(ftp_pasv_line)
    test.send_and_check(pkt4, proto_ip6_val, "Passive FTP PASV Response 4->6")

    # 10. Passive FTP PASV Response 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 6
    expect_payload = ftp_pasv_line
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / TCP(sport=21, dport=54000, flags="PA", seq=200) / Raw(ftp_pasv_line)
    test.send_and_check(pkt6, proto_ip4_val, "Passive FTP PASV Response 6->4")

    # BGP-4 OPEN Message (TCP 179): 16-byte marker (all 0xFF) + Len(2B) + Type=1 (1B) + Ver=4 + AS + HoldTime + BGP ID
    bgp_open = (b"\xFF" * 16) + struct.pack("!HBBHHI", 29, 1, 4, 65000, 180, 0xC0000201) + b"\x00"

    # 11. BGP-4 OPEN Message 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 6
    expect_payload = bgp_open
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / TCP(sport=179, dport=179, flags="PA", seq=300) / Raw(bgp_open)
    test.send_and_check(pkt4, proto_ip6_val, "BGP-4 OPEN Message 4->6")

    # 12. BGP-4 OPEN Message 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 6
    expect_payload = bgp_open
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / TCP(sport=179, dport=179, flags="PA", seq=300) / Raw(bgp_open)
    test.send_and_check(pkt6, proto_ip4_val, "BGP-4 OPEN Message 6->4")

    # NTP Datagram (UDP 123): 48 bytes standard NTP v4 packet (LI=0, VN=4, Mode=3 client / Mode=4 server)
    ntp_req = struct.pack("!BBBb", (0 << 6) | (4 << 3) | 3, 1, 4, -6) + (b"\x00" * 44)
    ntp_resp = struct.pack("!BBBb", (0 << 6) | (4 << 3) | 4, 1, 4, -6) + (b"\x00" * 44)

    # 13. NTP Datagram 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = ntp_req
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=123, dport=123) / Raw(ntp_req)
    test.send_and_check(pkt4, proto_ip6_val, "NTP Datagram 4->6")

    # 14. NTP Datagram 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = ntp_resp
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=123, dport=123) / Raw(ntp_resp)
    test.send_and_check(pkt6, proto_ip4_val, "NTP Datagram 6->4")

    # Syslog Datagram (UDP 514): RFC 5424 text string
    syslog_msg = b"<34>1 2026-10-17T22:00:00Z tayga-router test - - TAYGA CLAT syslog verification message\n"

    # 15. Syslog Datagram 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = syslog_msg
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=5140, dport=514) / Raw(syslog_msg)
    test.send_and_check(pkt4, proto_ip6_val, "Syslog Datagram 4->6")

    # 16. Syslog Datagram 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = syslog_msg
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=5140, dport=514) / Raw(syslog_msg)
    test.send_and_check(pkt6, proto_ip4_val, "Syslog Datagram 6->4")

    # SNMP Datagram (UDP 161): SNMPv2c GetRequest PDU
    # Sequence(38B) -> Version(1), Community("public"), GetRequest(24B) -> RequestID, ErrorStatus, ErrorIndex, VarbindList
    snmp_get = b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    snmp_resp = b"\x30\x26\x02\x01\x01\x04\x06public\xa2\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"

    # 17. SNMP GetRequest 4->6
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_nh = 17
    expect_payload = snmp_get
    pkt4 = IP(src=str(test.public_ipv4), dst=str(test.public_ipv6_xlate)) / UDP(sport=16100, dport=161) / Raw(snmp_get)
    test.send_and_check(pkt4, proto_ip6_val, "SNMP GetRequest 4->6")

    # 18. SNMP GetResponse 6->4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_nh = 17
    expect_payload = snmp_resp
    pkt6 = IPv6(src=str(test.public_ipv6), dst=str(test.public_ipv4_xlate)) / UDP(sport=161, dport=16100) / Raw(snmp_resp)
    test.send_and_check(pkt6, proto_ip4_val, "SNMP GetResponse 6->4")

    test.section("Layer 7: Application Protocol Verification")


# ============================================================================
# Main Execution & Reporting
# ============================================================================
def main():
    test.timeout = 0.2
    test.setup()

    sec_l4_sctp()
    sec_l4_udplite_dccp()
    sec_l4_mptcp_extended_tcp()
    sec_l4_quic()
    sec_l4_gre()
    sec_tunneling_ipsec_esp_natt()
    sec_tunneling_vxlan_geneve()
    sec_tunneling_ip_encap()
    sec_l3_edge_cases()
    sec_l7_application_patterns()

    time.sleep(1)
    test.cleanup()

    # 62 tests across 10 sections: all expected to pass cleanly
    test.report(62, 0)


if __name__ == "__main__":
    main()
