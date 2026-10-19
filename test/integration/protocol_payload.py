"""Select the bytes promised by the protocol fixtures, independent of Scapy bindings."""


def protocol_payload(protocol, data):
    """TCP/UDP fixtures compare application bytes; opaque protocols compare all bytes."""
    if protocol in (17, 136):
        if len(data) < 8:
            raise ValueError('truncated UDP/UDP-Lite header')
        return data[8:]
    if protocol == 6:
        if len(data) < 20:
            raise ValueError('truncated TCP header')
        offset = (data[12] >> 4) * 4
        if offset < 20 or offset > len(data):
            raise ValueError('invalid TCP header length')
        return data[offset:]
    if protocol == 33:
        if len(data) < 12:
            raise ValueError('truncated DCCP header')
        offset = data[4] * 4
        if offset < 12 or offset > len(data):
            raise ValueError('invalid DCCP header length')
        return data[offset:]
    return data
