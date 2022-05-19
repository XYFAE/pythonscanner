import sys
import requests
from main import main
#设置字体颜色:
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def start_main(url):
    # 更改输入的url加上http://或者https://
    if url.startswith("http://"):
        url = url       
    elif url.startswith("https://"):
        url = url
    else:
        url = "http://" + url
    try:
        r = requests.get(url, timeout=10)
        Status_code = r.status_code
        main(url, Status_code)
    except:
        print("url error")
        sys.exit()

if __name__ == '__main__':
    print(colors.WARNING+"===========================================================")
    print("===========================================================")
    print("===========================================================")
    print("================Welcome to use this scanner================")
    print("===========================================================")
    print("===========================================================")
    print("===========================================================")
    print("======================================"+colors.ENDC+colors.HEADER+"XYFAE-安全应急响应中心"+colors.ENDC)
    url = input("Please enter the url: ")
    start_main(url)
 