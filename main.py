from cgitb import handler
from logging import handlers
from traceback import print_tb
import requests
import sys
import socket
import threading
from tqdm import tqdm
import time
from whois import whois
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKRED = '\033[91m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"
    }

lock = threading.Lock()                     # 确保 多个线程在共享资源的时候不会出现脏数据
openNum = 0                                   # 端口开放数量统计
opendir = 0                                   # 目录开放数量统计
threads = []                                  # 线程池
ports = range(9999)
list1 = []
list2 = []

try:
    dir = open('dict.txt', 'r+', encoding='utf-8')
except:
    print(colors.OKRED+"Check whether the dict.txt file exists"+colors.ENDC)
    sys.exit()
def portscanner(host, port):
    global openNum
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        lock.acquire()
        openNum += 1
        list1.append("{} open".format(port))
        lock.release()
        s.close()
    except:
        pass

def dirscanner(url,i):
    global opendir
    #判断url最后一个字符是否为/ 没有则加上
    try:
        if url[-1] != '/':
            url = url + '/'
        newurl = url + i.strip('\n')
        
        r = requests.get(newurl, headers=headers)
        if r.status_code == 200:
            lock.acquire()
            list2.append("{} open".format(newurl))
            opendir += 1
            lock.release()
    except:
        pass
#输出当前网站的返回状态码
def main(url,Status_code):
    if Status_code == 200:
        print(colors.OKGREEN+"Status_code is: 200"+colors.ENDC)
        r1 = requests.get(url, headers=headers)
        ip = socket.gethostbyname(url.replace("http://", "").replace("https://", "").replace("/", ""))
        print('IP:', ip)

        socket.setdefaulttimeout(1)
        for port in tqdm(ports,colour='blue'):
            t1 = threading.Thread(target=portscanner, args=(ip, port))
            threads.append(t1)
            t1.start()
            # time.sleep(0.25)

        for t1 in threads:
           t1.join()
        
        print("端口开放列表为：")
        for i in list1:
            print(colors.OKGREEN+i+colors.ENDC)
            time.sleep(0.1)
        print(f"PortScan is Finish ,OpenNum is {openNum}")
        print("\n")
        # 返回当前服务器的信息
        print("The current server technologies are:" + r1.headers['Server']) # 返回当前服务器的信息

        # 查询whois信息
        """ whois = whois(url)
        print("当前网站的whois信息为：" + whois.text) """

        # 判断脚本语言
        if "X-Powered-By" in str(r1.headers):
            print("The server uses a scripting language: " +colors.OKGREEN+r1.headers["X-Powered-By"]+colors.ENDC)   # 脚本语言

        # 寻找网站后台

        print("Looking for the background of the current website, please wait...")  # 寻找网站后台

        for i in tqdm(dir.readlines() , colour='blue'):
            t2 = threading.Thread(target=dirscanner, args=(url,i))
            threads.append(t2)
            t2.start()
            # time.sleep(0.25)

        for t2 in threads:
            t2.join()

        if opendir != 0:
            for j in list2:
                print(colors.OKGREEN+j.replace("\n","")+colors.ENDC)
                time.sleep(0.1)
        else:
            print(colors.OKRED+"No directory found"+colors.ENDC)

        print(f"DirScan is Finish ,OpenNum is {opendir}")

        # 扫描网站是否存在ms15-034漏洞,目前仅仅增加了一个。之后可以自定义函数调用，增加多个
        print()
        print("正在测试当前网站是否存在ms15-034...")
        r3 = requests.get(url)
        server = r3.headers["Server"]
        if server.find("IIS/7.5") or server.find("IIS/8.0"):
            payloay = {"Host": "irrelevant",
                    "Range": "bytes=0-18446744073709551615"}  # 注意字典内容格式
            r3 = requests.get(url, headers=payloay)
            if "Requested Range Not Satisfiable" in r3.text:
                print("检测存在ms15-034")
            else:
                print("未检测到ms15-034")
        else:
            print("服务器组件不是IIS 7.5或者IIS 8.0")

    else:
        print("Status_code:" + str(Status_code))
