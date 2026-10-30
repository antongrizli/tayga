#!/usr/bin/env python3
"""Unsigned deterministic DNS upstream for disposable DNS64 integration tests."""
import socket
import struct


def wire(name):
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(('127.0.0.1', 5300))
    while True:
        packet, peer = server.recvfrom(4096)
        if len(packet) < 12:
            continue
        cursor = 12
        labels = []
        try:
            while packet[cursor]:
                length = packet[cursor]
                cursor += 1
                labels.append(packet[cursor:cursor + length].decode('ascii').lower())
                cursor += length
            cursor += 1
            qtype, qclass = struct.unpack('!HH', packet[cursor:cursor + 4])
            question = packet[12:cursor + 4]
        except (IndexError, ValueError, UnicodeError, struct.error):
            continue
        name = '.'.join(labels)
        addresses = {'ipv4only.arpa': ('192.0.0.170', '192.0.0.171'), 'service.example.com': ('1.1.1.1',)}
        answers = b''
        authority = b''
        count = 0
        flags = 0x8580
        if name not in addresses or qclass != 1:
            flags |= 3
        elif qtype == 1:
            for address in addresses[name]:
                answers += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(address)
                count += 1
        else:
            soa = wire('ns.invalid') + wire('hostmaster.invalid') + struct.pack('!IIIII', 1, 3600, 600, 86400, 60)
            authority = b'\xc0\x0c' + struct.pack('!HHIH', 6, 1, 60, len(soa)) + soa
        header = packet[:2] + struct.pack('!HHHHH', flags, 1, count, int(bool(authority)), 0)
        server.sendto(header + question + answers + authority, peer)
