#!/usr/bin/env python

"""nmap TCP port scan with Scapy"""

import argparse
import ipaddress
import sys
from scapy.layers.inet import IP, ARP, Ether, TCP
from scapy.sendrecv import sr1, srp
from scapy.volatile import RandShort


def nmap(destination):
    """
    nmap

    :destination: nmap's destination

    """

    ip = parse_ip_str_to_ip_address(destination)
    mac = "({})".format(get_mac_address_from_ip(ip))
    print "Scanning {} {}...".format(ip, mac)

    for port in range(78, 85):
        packet = IP(dst=str(ip)) / TCP(flags='S',
                                       sport=RandShort(), dport=port)
        resp = sr1(packet, verbose=0, timeout=5)

        if resp is None or not resp.haslayer(TCP):
            print "Port {} is ???".format(port)
            continue  # error?

        # check for SYN(2) and ACK(16) flags set (open port)
        if resp[TCP].flags & 2 and resp[TCP].flags & 16:
            # TODO close the connection, check seq from response etc.
            # sr1(IP(dst=str(ip)) / TCP(flags='F',
                                      # dport=port), verbose=0, timeout=3)
            print "Port {} is open".format(port)
        # check for RST(4) flag set (open port)
        elif resp[TCP].flags & 4:
            print "Port {} is closed".format(port)
        else:
            print "Port {} is ???".format(port)


def parse_ip_str_to_ip_address(destination):
    """ parses destination IP address to ipaddress.ip_address type

    :destination: string representation of IP address of host
    :returns: parsed IP address of host

    """

    try:
        ip = ipaddress.ip_address(unicode(destination))
        return ip
    except ValueError as e:
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
    nmap TCP port scan with Scapy
    """

    parser = argparse.ArgumentParser(
        description="nmap TCP port scan with Scapy")
    parser.add_argument("destination",
                        help="IP address of host e.g. 192.168.1.1",
                        type=str)
    args = parser.parse_args()

    nmap(destination=args.destination)

if __name__ == "__main__":
    main()
