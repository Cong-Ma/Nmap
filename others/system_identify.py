# @DateTime:2022/8/10 16:28
# @File:system_identify.py


import re
import os


def system_scan(iplist):
    try:
        ttlstrmatch=re.compile(r'ttl=\d+',re.I)
        ttlvaluematch=re.compile(r'\d+',re.I)
        for ip in iplist:
            file_obj=os.popen("ping "+ip)
            whole_text=file_obj.read()
            flag=0
            for line in whole_text.splitlines():
                result=ttlstrmatch.findall(line)
                if result:
                    ttl=ttlvaluematch.search(result[0]).group()
                    if int(ttl)<=64:
                        print(ip+" is Linux/UNIX")
                        flag=1
                        break
                    else:
                        print(ip+" is Windows")
                        flag=1
                        break
            if flag==0:
                print("Can't connect to "+ip)
    except:
        print("Something error in file:"+__file__+" function:"+__name__)