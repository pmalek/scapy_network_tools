#!/usr/bin/env python

"""tcptraceroute with Scapy"""

import argparse
import socket
from scapy.layers.inet import UDP, IP, TCP
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


def tcptraceroute(host, timeout, maxttl=30):
    """tcptraceroute sends TCP messages with SYN flag set
    to host with increasing TTL until it reaches destination
    host or reaches maxttl

    :host: traceroute's destination

    """

    ip = resolve_dns_to_ip(host)

    print "tcptraceroute to '{}' ({}), {} hops max".format(host, ip, maxttl)
    for i in range(1, maxttl + 1):
        packet = IP(dst=ip, ttl=i) / TCP(flags='S')
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
    tcptraceroute using scapy
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
        tcptraceroute(host=args.destination,
                      timeout=args.timeout, maxttl=args.maxttl)
    except socket.gaierror as e:
        print "DNS resolution failed: '{}'".format(e)

if __name__ == "__main__":
    main()
