# @DateTime:2022/8/9 22:58
# @File:udp.py

import random
from scapy.layers.inet import IP, UDP
from scapy.all import sr1


def udp_scan(iplist):
    open_iplist = []
    try:
        for ip in iplist:
            dest_port = random.randint(1, 65535)
            packet = IP(dst=ip) / UDP(dport=dest_port)
            response = sr1(packet, timeout=1.0, verbose=0)
            if response:
                if int(response.proto == 1):
                    print(ip + " is up")
                    open_iplist.append(ip)
                else:
                    print(ip + " is down")
            else:
                print(ip + " no response")
    except:
        print("Something error in file:"+__file__+" function:"+__name__)
    print("\nresult:")
    if len(open_iplist) != 0:
        for open_ip in open_iplist:
            print(open_ip + " is up")
    else:
        print("All hosts are down")
