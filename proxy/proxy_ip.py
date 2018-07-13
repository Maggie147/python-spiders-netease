# -*- coding: utf-8 -*-
import os
import re
import sys
import json
import requests
from bs4 import BeautifulSoup
from multiprocessing.dummy import Pool


class ProxyIP(object):
    def __init__(self, timeout=30):    
        self.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.check_session = requests.Session()
        self.check_session.keep_alive = False
        self.timeout = timeout


    def my_request(self, url, params=None, json=False):
        """
        封装requests请求
        """
        if not params:
            resp = self.session.get(url, timeout=self.timeout)
        else:
            resp = self.session.post(url, data=params, timeout=self.timeout)
            # resp.encoding = 'utf-8'
        if not json:
            return resp.text
        else:
            return resp.json

    def get_proxys_gather(self):
        """
        获取'gatherproxy'免费代理IP (貌似已失效)
        """
        url = "http://www.gatherproxy.com/zh/"
        result = self.my_request(url)
        proxy_rule = r'gp.insertPrx\((.*?)\)'
        proxy_json = re.findall(proxy_rule, result, re.S | re.M)
        proxy_ips = []
        for p in proxy_json:
            ip = json.loads(p)["PROXY_IP"]
            port = json.loads(p)["PROXY_PORT"]
            ip_info = "{ip}:{port}".format(ip=ip, port=int(port, 16))
            proxy_ips.append(ip_info)
        return proxy_ips


    def get_proxys_xici(self):
        """
        :desc
            获取西刺免费代理IP
        :return
            result  - 代理列表
        :modify:
            2018-07-13
        """
        url = "http://www.xicidaili.com/nn/1"
        resp = self.my_request(url)
        soup = BeautifulSoup(resp, 'lxml')
        tr_list = soup.findAll('tr')
        result = []
        for item in enumerate(tr_list[1:]):
            td_list = item[1].findAll('td')
            ip = td_list[1].contents[0] if td_list[1].contents[0] else ''
            if not self._format_check(ip):
                continue
            port = td_list[2].contents[0] if td_list[2].contents[0] else ''
            if not self._format_check(port, port=True):
                print port
                continue
            result.append("{ip}:{port}".format(ip=ip, port=port))
        return result

    def _ping_check_ip(self, ip):
        """
        :desc
            检查代理IP的连通性, 去除潮湿大于200的IP. windows
        :params
            ip - 代理的ip地址
        :return
            ip - 有效的IP
        """
        import subprocess as sp
        re_lose = re.compile(u"丢失 = (\d+)", re.IGNORECASE)  # 匹配丢包数
        re_waste = re.compile(u"平均 = (\d+)ms", re.IGNORECASE)  # 匹配平均时间
        cmd = 'ping -n 3 -w 3 %s'
        p = sp.Popen(cmd % ip, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True) 
        out = p.stdout.read().decode("gbk")
        lose_time = re_lose.findall(out)
        if len(lose_time) == 0:
            lose = 3
        else:
            lose = int(lose_time[0])
        if lose > 2:
            # return 1000
            pass
        else:
            average = re_waste.findall(out)
            if len(average) == 0:
                pass
            else:
                if int(average[0]) > 200:
                    pass
                else:
                    return ip

    def _check_ip(self, ip):
        """
        检查IP是否有效
        """
        url= "http://ip.chinaz.com/getip.aspx"
        proxies = {"http": "http://" + ip}
        try:
            resp = self.check_session.get(url, proxies=proxies, timeout=5)
            if "window.location" not in resp.text:
                return ip
        except Exception as e:
            pass

    def _format_check(self, data, port=False):
        """
        通过格式判断检查IP
        """
        try:
            if not port:
                # simple check ip
                if data.count('.') == 3:
                    return True
            else:
                # simple checke port
                try:
                    int(data)
                    return True
                except Exception as e:
                    pass            
        except Exception as e:
            print(e)
        return False

    def get_valid_ip(self, src_ips):
        """
        :desc
            过滤出有效的代理IP
        :params
            src_ips - 需要过滤的代理IP
        :return:
            ips    -  有效的IP
        """        
        ips = []
        if not src_ips:
            return ips
        num = len(src_ips)
        try:
            pool = Pool(num)
            result = pool.map(self._check_ip, src_ips)
            pool.close()
            pool.join()
            ips = [ip for ip in result if ip]            
        except Exception as e:
            print(e)
        return ips


    def save_file(self, datas, fpath, fname):
        """
        :desc
            将数据保存文件
        :params
            datas - 需要保存的数据
            fpath - 文件路径
            fname - 文件名
        :return:
            是否保存成功的标识 
        """  
        if not os.path.exists(fpath):
            os.makedirs(fpath)
        try:
            fullpath = os.path.join(fpath, fname)
            with open(fullpath, 'wb') as fp:
                for item in datas:
                    fp.write(item+'\r\n')
            return True
        except Exception as e:
            print(e)
            return False


def main():
    output = 'Proxy_File'
    fname = 'ProxyIP.txt'
    proxyip = ProxyIP()

    # 爬去代理IP数据
    print('Gets ip list...')
    ip_list = proxyip.get_proxys_xici()  # ip_list = proxyip.get_proxys_gather()
    if not ip_list:
        print('get ip_list failed!')
        sys.exit(1)

    # 过滤无效的IP
    print('Check ip alive...')
    ips = proxyip.get_valid_ip(ip_list)
    if not ips:
        print('Not get valid ip!')
        sys.exit(1)

    # 保存为txt
    ret = proxyip.save_file(ips, output, fname)
    if not ret:
        print("Save {file} failed!".format(file=fname))
        sys.exit(1)
    print('Save to {file}'.format(file=fname))


if __name__ == "__main__":
    main()
