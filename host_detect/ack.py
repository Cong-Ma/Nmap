# @DateTime:2022/8/9 22:22
# @File:ack.py


import random
from scapy.layers.inet import IP, TCP
from scapy.all import sr1


def ack_scan(iplist):
    open_iplist = []
    try:
        for ip in iplist:
            dest_port = random.randint(1, 65535)
            packet = IP(dst=ip) / TCP(flags="A", dport=dest_port)
            response = sr1(packet, timeout=1.0, verbose=0)  # sr1表示只接收第一个回复
            if response:  # verbose=0表示不显示那么多杂乱的信息
                if int(response[TCP].flags == 4):
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
