#!/usr/bin/env python

"""nmap with Scapy"""

import argparse
import ipaddress
import sys
from scapy.layers.inet import IP, ICMP, ICMPerror, ARP, Ether
from scapy.sendrecv import sr1, srp


def nmap(destination):
    """nmap

    :destination: nmap's destination

    """

    ips = parse_ip_to_network(destination)
    for ip in ips:
        packet = IP(dst=str(ip)) / ICMP()
        resp = sr1(packet, verbose=0, timeout=1)
        if resp is not None:
            mac = ""
            if not resp.haslayer(ICMPerror):
                ok = "up"
                mac = "({})".format(get_mac_address_from_ip(ip))
            else:
                ok = "down"

            print "Host {} {} is {}".format(ip, mac, ok)


def parse_ip_to_network(destination):
    """ parses ip to ipaddress.ip_network type

    :destination: string representation of IP address of host/network
    :returns: parsed IP address of host/network

    """

    try:
        ip = ipaddress.ip_network(unicode(destination), strict=False)
        return ip
    except ipaddress.AddressValueError as e:
        print "Problem parsing destination {}\nError: {}".format(destination, e)
        sys.exit(1)


def get_mac_address_from_ip(ip):
    """
    resolves mac address from ip
    (since there is no way to get it directly from ICMP reply in scapy (or is there?))

    :ip: IP address to get MAC resolvem from
    :returns: MAC address or None in case of failure

    """

    a, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
               ARP(pdst=str(ip)), timeout=1, verbose=False)
    if len(a) > 0 and a[0][1].haslayer(Ether):
        return a[0][1][Ether].hwsrc
    return None


def main():
    """
    nmap using scapy
    """

    parser = argparse.ArgumentParser(description="nmap with Scapy")
    parser.add_argument("destination",
                        help="IP address of host/network e.g. 192.168.1.1, 10.0.0.1/24",
                        type=str)
    args = parser.parse_args()

    nmap(destination=args.destination)

if __name__ == "__main__":
    main()
