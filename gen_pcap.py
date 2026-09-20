import io
import time
import socket
import dpkt
import os

f = io.BytesIO()
writer = dpkt.pcap.Writer(f)

tcp = dpkt.tcp.TCP(
    sport=49152, dport=443, flags=dpkt.tcp.TH_SYN,
    seq=1000, ack=0, win=8192, data=b"GET / HTTP/1.1\r\n\r\n"
)

ip = dpkt.ip.IP(
    v=4, hl=5, p=dpkt.ip.IP_PROTO_TCP,
    src=socket.inet_aton("10.10.10.50"),
    dst=socket.inet_aton("185.220.101.45"),
    data=tcp
)
ip.len = len(ip)

eth = dpkt.ethernet.Ethernet(
    src=b'\x00\x11\x22\x33\x44\x55',
    dst=b'\x66\x77\x88\x99\xaa\xbb',
    type=dpkt.ethernet.ETH_TYPE_IP,
    data=ip
)

writer.writepkt(eth, time.time())
f.seek(0)

os.makedirs('tests/fixtures', exist_ok=True)
with open('tests/fixtures/sample.pcap', 'wb') as out:
    out.write(f.getvalue())
