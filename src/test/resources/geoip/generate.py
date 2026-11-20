"""Generate synthetic MMDB fixtures. Python standard library only; no real GeoIP data.
Run from any directory: python audit/testdata/geoip/generate.py
"""
import ipaddress
from pathlib import Path

def head(t, n):
    extra = b"" if t < 8 else bytes([t-7])
    if n < 29: return bytes([((t if t < 8 else 0) << 5) | n]) + extra
    if n < 285: return bytes([((t if t < 8 else 0) << 5) | 29]) + extra + bytes([n-29])
    raise ValueError(n)

def enc(x):
    if isinstance(x, str):
        b = x.encode(); return head(2, len(b)) + b
    if isinstance(x, dict): return head(7, len(x)) + b"".join(enc(k)+enc(v) for k,v in x.items())
    if isinstance(x, list): return head(11, len(x)) + b"".join(enc(v) for v in x)
    t, n = x; b = n.to_bytes((n.bit_length()+7)//8, "big"); return head(t, len(b)) + b

def write(kind, record):
    root = {}
    for cidr in ["8.8.8.0/24", "2606:4700::/32"]:
        net = ipaddress.ip_network(cidr); bits = bin(int(net.network_address))[2:].zfill(net.max_prefixlen)
        if net.version == 4: bits = "0"*96 + bits
        node = root
        for bit in bits[:net.prefixlen + (96 if net.version == 4 else 0)]: node = node.setdefault(int(bit), {})
        node["value"] = True
    nodes = []
    def assign(n):
        if "value" in n: return
        n["idx"] = len(nodes); nodes.append(n)
        for bit in [0,1]:
            if bit in n: assign(n[bit])
    assign(root); count = len(nodes)
    tree = bytearray()
    for n in nodes:
        for bit in [0,1]:
            child = n.get(bit)
            ref = count if child is None else count+16 if "value" in child else child["idx"]
            tree += ref.to_bytes(3,"big")
    meta = {"binary_format_major_version":(5,2), "binary_format_minor_version":(5,0),
            "build_epoch":(9,1793491200), "database_type":"DBIP-"+kind+"-Lite",
            "description":{"en":"Synthetic DB-IP-compatible test fixture (not DB-IP data)"},
            "ip_version":(5,6), "languages":["en"], "node_count":(6,count), "record_size":(5,24)}
    Path(__file__).with_name(kind.lower()+".mmdb").write_bytes(tree + bytes(16) + enc(record) + bytes.fromhex("abcdef") + b"MaxMind.com" + enc(meta))

write("Country", {"country":{"iso_code":"US", "names":{"en":"Example Country"}}})
write("ASN", {"autonomous_system_number":(6,64500), "autonomous_system_organization":"Example Network"})
