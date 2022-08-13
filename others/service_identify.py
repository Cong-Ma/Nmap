# @DateTime:2022/8/10 15:30
# @File:service_identify.py


import socket
import re


SIGNS = (
    # 协议 版本 关键字
    b'FTP|FTP|^220.*FTP',  # b表示bytes类型
    b'MySQL|MySQL|mysql_native_password',  # 索引为1的是服务名,索引为-1的是服务的关键字
    b'oracle-https|^220- ora',
    b'Telnet|Telnet|Telnet',
    b'Telnet|Telnet|^\r\n%connection closed by remote host!\x00$',
    b'VNC|VNC|^RFB',
    b'IMAP|IMAP|^\* OK.*?IMAP',
    b'POP|POP|^\+OK.*?',
    b'SMTP|SMTP|^220.*?SMTP',
    b'Kangle|Kangle|HTTP.*kangle',
    b'SMTP|SMTP|^554 SMTP',
    b'SSH|SSH|^SSH-',
    b'HTTPS|HTTPS|Location: https',
    b'HTTP|HTTP|HTTP/1.1',
    b'HTTP|HTTP|HTTP/1.0'
)



def regex(response,port):
    try:
        proto=""
        flag=0
        if re.search(b'<title>502 Bad Gateway',response):
            proto="Service failed to access!"
        for item in SIGNS:
            itemlist=item.split(b'|')
            if re.search(itemlist[-1],response,re.I):
                proto="["+str(port)+"] open "+itemlist[1].decode()
                flag=1
                break
        if flag==0:
            proto="["+str(port)+"] open unrecognized"
        print(proto)
    except:
        print("Something error in file:"+__file__+" function:"+__name__)



def service_scan(iplist,portlist):
    try:
        for ip in iplist:
            for port in portlist:
                probe='GET / HTTP/1.0\r\n\r\n'
                sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sock.settimeout(5)
                result_code=sock.connect_ex((ip,port))
                if result_code==0:
                    try:
                        sock.sendall(probe.encode())
                        response=sock.recv(256)
                        if response:
                            regex(response,port)
                    except(ConnectionResetError,socket.timeout):
                        print("Port "+port+" timeout")
                else:
                    pass
    except:
        print("Something errer")