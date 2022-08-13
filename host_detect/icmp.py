# @DateTime:2022/8/9 23:08
# @File:icmp.py

import random
from scapy.layers.inet import IP, ICMP
from scapy.all import sr1


def icmp_scan(iplist):
    open_iplist = []
    try:
        ip_id = random.randint(1, 65535)
        icmp_id = random.randint(1, 65535)
        icmp_seq = random.randint(1, 65535)
        for ip in iplist:
            packet = IP(dst=ip, id=ip_id) / ICMP(id=icmp_id, seq=icmp_seq) / b'rookit'
            result = sr1(packet, timeout=1, verbose=0)
            if result:
                for rcv in result:
                    scan_ip = rcv[IP].src
                    print(scan_ip + " is up")
                    open_iplist.append(scan_ip)
            else:
                print(ip + " is down")
    except:
        print("Something error in file:"+__file__+" function:"+__name__)
    print("\nresult:")
    if len(open_iplist) != 0:
        for open_ip in open_iplist:
            print(open_ip + " is up")
    else:
        print("All hosts are down")
