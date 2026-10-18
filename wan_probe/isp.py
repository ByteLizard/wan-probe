"""ISP identity per WAN, learned through the WAN itself.

One marked UDP DNS query (the WAN's DSCP, so it leaves on that WAN) asks a
public resolver for the address it sees us as; Team Cymru's DNS ASN
service then maps that address to an ASN and an organisation. Hand-built
DNS because the stdlib resolver cannot set TOS or fetch TXT records.
"""
import os
import re
import socket
import struct


def _qname(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.strip(".").split(".")) + b"\0"


def build_query(name, qtype, qid):
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + _qname(name) + struct.pack("!HH", qtype, 1)


def parse_answers(resp, qid=None):
    """Return answer rdata list: A records as dotted quads, TXT as strings."""
    if len(resp) < 12:
        raise ValueError("short DNS response")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", resp[:12])
    if qid is not None and rid != qid:
        raise ValueError("DNS id mismatch")
    if flags & 0x000F:
        raise ValueError(f"DNS rcode {flags & 0x000F}")

    def skip_name(offset):
        while True:
            length = resp[offset]
            if length == 0:
                return offset + 1
            if length & 0xC0 == 0xC0:
                return offset + 2
            offset += 1 + length

    offset = 12
    for _ in range(qd):
        offset = skip_name(offset) + 4
    out = []
    for _ in range(an):
        offset = skip_name(offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", resp[offset:offset + 10])
        offset += 10
        rdata = resp[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            out.append(socket.inet_ntoa(rdata))
        elif rtype == 16:
            index = 0
            text = b""
            while index < len(rdata):
                length = rdata[index]
                text += rdata[index + 1:index + 1 + length]
                index += 1 + length
            out.append(text.decode(errors="replace"))
    return out


def dns_query(server, name, qtype, tos=None, timeout=3.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if tos is not None:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
        sock.settimeout(timeout)
        qid = int.from_bytes(os.urandom(2), "big")
        sock.sendto(build_query(name, qtype, qid), (server, 53))
        resp, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return parse_answers(resp, qid)


def system_resolver(path="/etc/resolv.conf"):
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return "127.0.0.1"


def public_address(tos, resolver="208.67.222.222", name="myip.opendns.com"):
    answers = dns_query(resolver, name, 1, tos=tos)
    return answers[0] if answers else None


def asn_lookup(address, resolver=None):
    """(asn, organisation) for an IPv4 address via Team Cymru, or (None, None)."""
    resolver = resolver or system_resolver()
    reversed_ip = ".".join(reversed(address.split(".")))
    origin = dns_query(resolver, f"{reversed_ip}.origin.asn.cymru.com", 16)
    if not origin:
        return None, None
    asn = origin[0].split("|")[0].strip()
    if not asn.isdigit():
        return None, None
    detail = dns_query(resolver, f"AS{asn}.asn.cymru.com", 16)
    org = detail[0].split("|")[-1].strip() if detail else ""
    return int(asn), org


def slug_from_org(org):
    """'TILLLMAN-FIBER-CO - TILLMAN FIBERCO, LLC, US' -> 'tillman'."""
    if not org:
        return "unknown"
    text = org.split(" - ", 1)[-1] if " - " in org else org
    words = re.findall(r"[a-z0-9]+", text.lower())
    skip = {"llc", "inc", "us", "ltd", "co", "the", "corp", "corporation", "company"}
    for word in words:
        if word not in skip:
            return word
    return words[0] if words else "unknown"


def identify(tos, overrides=None, resolver="208.67.222.222", name="myip.opendns.com"):
    """{address, asn, org, isp} for one WAN. overrides: a slug to force."""
    address = public_address(tos, resolver=resolver, name=name)
    asn, org = (None, None)
    if address:
        asn, org = asn_lookup(address)
    slug = overrides or slug_from_org(org)
    return {"address": address, "asn": asn, "org": org, "isp": slug}
