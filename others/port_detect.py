# @DateTime:2022/8/9 22:43
# @File:port_detect.py


import threading
import queue
import socket


class PortScanner(threading.Thread):
    def __init__(self, portqueue, ip, timeout=3):
        threading.Thread.__init__(self)
        self._portqueue = portqueue
        self._ip = ip
        self._timeout = timeout

    def run(self):
        while True:
            if self._portqueue.empty():
                break
            port = self._portqueue.get(timeout=3)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # print(type(port),port)    # 这里的port都是str,不是int
            try:
                sock.settimeout(self._timeout)
                result_code = sock.connect_ex((self._ip, port))
                if result_code == 0:
                    print("Port %d is open" % port)

                else:
                    print("Port %d is closed" % port)
            except Exception as e:
                print(e)
            finally:
                sock.close()


def port_scan(iplist, portlist, threadnum):
    try:
        portqueue = queue.Queue()
        for port in portlist:
            portqueue.put(port)
        for ip in iplist:
            threadlist = []
            for _ in range(threadnum):
                threadlist.append(PortScanner(portqueue, ip))

            for thread in threadlist:
                thread.start()
            for thread in threadlist:
                thread.join()
    except:
        print("Something error in file:" + __file__ + " function:" + __name__)

