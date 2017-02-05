#!/usr/bin/env python

"""traceroute with Scapy"""

import argparse
import socket
from scapy.layers.inet import UDP, IP, ICMP
from scapy.sendrecv import sr1, sr
from scapy.layers.dns import DNSRR, DNSQR, DNS


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


def traceroute(host, timeout, maxttl=30):
    """traceroute sends ICMP ping packages to host with
    increasing TTL until it reaches destination host
    or reaches maxttl

    :host: traceroute's destination

    """

    ip = resolve_dns_to_ip(host)

    print "traceroute to '{}' ({})".format(host, ip)
    for i in range(1, maxttl + 1):
        packet = IP(dst=ip, ttl=i) / ICMP()
        resp, _ = sr(packet, verbose=0, timeout=timeout)
        src = "*"
        duration = ""
        if len(resp) > 0:
            src = resp[0][1].src
            duration = "{:.3f} ms".format(
                1000 * (resp[0][1].time - resp[0][0].sent_time))
        print "{:2d}. {:>15}\t{}".format(i, src, duration)
        if src == ip:
            return
    print "Couldn't traceroute {}, reached max TTL '{}'".format(ip, maxttl)


def main():
    """
    traceroute using scapy
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--destination", help="host/IP to send ping to",
                        type=str, required=True)
    parser.add_argument("-t", "--timeout", help="timeout in seconds",
                        type=int, default=1)
    parser.add_argument("-m", "--maxttl", help="max TTL",
                        type=int, default=30)
    args = parser.parse_args()

    try:
        traceroute(host=args.destination,
                   timeout=args.timeout, maxttl=args.maxttl)
    except socket.gaierror as e:
        print "DNS resolution failed: '{}'".format(e)

if __name__ == "__main__":
    main()
