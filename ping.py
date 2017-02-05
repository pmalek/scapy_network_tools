#!/usr/bin/env python

"""ICMP ping utility with Scapy"""

import argparse
import socket
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.sendrecv import sr, sr1


def resolve_dns_to_ip(host):
    """resolves host to IP address

    :host: hostname to be resolved
    :returns: IP address of resolved host

    """
    dns_resp = sr1(IP(dst="8.8.8.8") / UDP(dport=53) /
                   DNS(rd=1, qd=DNSQR(qname=host)), verbose=0)
    for i in range(dns_resp[DNS].ancount):
        if dns_resp[DNSRR][i].type == 1:  # A record
            return dns_resp[DNSRR][i].rdata
    return None


def create_packet_with_MTU_flags(host, mtu_flags):
    """
    creates ICMP packet with MTU flags
    """

    if mtu_flags == "do":
        return IP(dst=host, flags="DF") / ICMP()
    return IP(dst=host) / ICMP()


def ping(host, count, flags):
    """ping send count number of ICMP messages to host

    :host: ping's destination
    :count: number of ping messages to send
    :flags: MTU discovery strategy flags

    """

    ip = resolve_dns_to_ip(host)
    print "PING {} ({}), {} times".format(host, ip, count)
    packet = create_packet_with_MTU_flags(host, flags)
    for i in range(count):
        r, _ = sr(packet, verbose=0)
        sent = r[0][0].sent_time
        received = r[0][1].time
        print "{:2}. from {}: {} {:.3f}ms".format(i, r[0][1].src, len(r), 1000 * (received - sent))


def main():
    """
    ping.py imitates Linux command line tool 'ping'
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--count", help="number of ICMP ping messages to be sent",
                        type=int, default=1)
    parser.add_argument("-d", "--destination", help="host/IP to send ping to",
                        type=str, required=True)
    parser.add_argument("-M", help="path MTU discovery strategy",
                        type=str, default="")
    args = parser.parse_args()

    try:
        ping(host=args.destination, count=args.count, flags=args.M)
    except socket.gaierror as e:
        print "DNS resolution failed: '{}'".format(e)

if __name__ == "__main__":
    main()
