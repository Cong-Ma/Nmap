# @DateTime:2022/8/9 17:52
# @File:nmap.py


import sys

# print(sys.path)
sys.path.append('../')  # python解释器会导入sys.path中所有路径下的模块,但是在nmap文件夹下是无法导入nmap模块的.
# print(sys.path)     #因此添加../目录作为其中一个工作目录,使解释器也在../目录下导入模块,就能导入nmap模块.

import argparse
from NmapTool.host_detect.ack import ack_scan
from NmapTool.host_detect.udp import udp_scan
from NmapTool.host_detect.icmp import icmp_scan
from NmapTool.others.port_detect import port_scan
from NmapTool.others.service_identify import service_scan
from NmapTool.others.system_identify import system_scan


def ack_host_detect(iplist):
    ack_scan(iplist)


def syn_host_detect(iplist):
    pass


def udp_host_detect(iplist):
    udp_scan(iplist)


def icmp_host_detect(iplist):
    icmp_scan(iplist)


def port_detect(iplist, portlist):
    threadnum = int(input("Please input threadnum\n"))
    port_scan(iplist, portlist, threadnum)


def service_identify(iplist, portlist):
    service_scan(iplist, portlist)


def system_identify(iplist):
    system_scan(iplist)


def parse(option, ip, port):
    # 先处理ip
    iplist = []
    if '-' in ip:  # -i 192.168.0.1-128
        for i in range(int(ip.split('-')[0].split('.')[3]), int(ip.split('-')[1]) + 1):  # 取出1-128
            iplist.append(ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.' + str(i))
    else:
        iplist.append(ip)

    # 再处理port
    portlist = []
    if '-' in port:  # -p  20-1000
        portlist.append(range(int(port.split('-')[0]), int(port.split('-')[1]) + 1))
    elif ',' in port:  # -p  22,80,443
        for port in port.split(','):
            portlist.append(int(port))  # 一定要将str类型的port转换为int类型
    else:
        portlist.append(int(port))

    # 最后处理具体行为
    if option == "sA":
        ack_host_detect(iplist)
    if option == "sS":
        syn_host_detect(iplist)
    if option == "sU":
        udp_host_detect(iplist)
    if option == "sP":
        icmp_host_detect(iplist)

    if option == "PA":
        port_detect(iplist, portlist)
    if option == "PS":
        service_identify(iplist, portlist)
    if option == "OS":
        system_identify(iplist)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-op", "--option", dest="option", type=str, default="sA",
                        help="specify the mode  指定具体功能\r\nsA:基于TCP的ACK存活主机探测\r\nsS:基于TCP的SYN存活主机探测\r\nsU:基于UDP的存活主机探测\r\nsP:基于ICMP的存活主机探测\r\nPA:存活端口探测\r\nPS:识别端口服务信息\r\nOS:识别操作系统版本")
    parser.add_argument("-i", "--ip", dest="targetIP", type=str, default="127.0.0.1",
                        help="specify the IP address  指定目标IP地址范围")
    parser.add_argument("-p", "--port", dest="targetPort", type=str, default="80,443,3306,3389",
                        help="specify port range  指定端口范围")
    args = parser.parse_args()
    parse(args.option, args.targetIP, args.targetPort)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user!")
