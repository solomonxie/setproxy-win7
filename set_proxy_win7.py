#!/usr/bin/env python2
# -*- coding: utf-8 -*-

'''
    # Title : Set Proxy on Windows 7 Through Registry
    # Author: Solomon Xie
'''
# === 必备模块 ===
import urllib2, urllib, re, os, sys, time, random, datetime, getopt
import requests # 第三方
from threading import Thread
from bs4 import BeautifulSoup # 第三方


def main():
    # print Proxy('192.168.1.1:8080').ieProxy('ProxyOnly')
    opts, args = getopt.getopt(sys.argv[1:], 'p:a',['pac=', 'off'])
    # print opts #调试用
    for o,a in opts:
        if   o == '-p':    print Proxy(a).ieProxy('ProxyOnly')
        elif o == '-a':    print Proxy().ieProxy('PacOnly')
        elif o == '--pac': print Proxy(pac=a).ieProxy('PacOnly')
        elif o == '--off': print Proxy().ieProxy('Off')
    # ProxyPool().update()
    # for i in ProxyPool().getProxies(): print Proxy(i).check()

class Proxy():
    def __init__(self, uri='', pac=''):
        self.pto    = 'https' if 'https' in uri else 'http'
        self.host   = ''.join(re.findall('\d+\.\d+\.\d+\.\d+', uri))
        self.port   = ''.join(re.findall('[:\s]+(\d+)', uri))
        self.adr    = (self.host +':'+ self.port) if self.host and self.port else ''
        self.proxy  = {self.pto: self.adr}
        self.uri    = self.pto+'://'+self.adr
        self.pac    = pac if pac else 'https://pac.itzmx.com/abc.pac'

    def check(self):
        '''
        Function: 在线或在本地服务器网站（为了快速），检验IP是否可用、是否统一、是否高匿等
        Notes   : 先到网站上获取本机真实IP再做对比
                  验证通过返回True，失败则返回False。
        '''
        if not self.adr: return -1
        # 先关上本地已设置的所有代理再开始验证
        # self.ieProxy('Off')
        # 第一重验证：ping
        print 'Pinging %s'%self.host
        icmp = os.popen('ping %s'%self.host).read()
        resu = re.findall( '(\d+)ms[^\d]+(\d+)ms[^\d]+(\d+)ms', icmp )
        # print icmp
        if len(resu) < 1: return -1 # 如果没有ping通，则直接中断下一步检测
        speed = resu[0][-1]
        # 第四重验证: 打开google验证是否能翻墙
        print 'Connecting web outside GFW by %s'%self.adr
        try: r = requests.get('http://www.ip.cn', headers=getHeader(), proxies=self.proxy, timeout=3)
        except Exception as e: return 0
        os.popen('start chrome https://www.google.com/#newwindow=1&q=%s'%self.adr)
        # 第三重验证：打开验证公网IP的网站
        print 'Connecting web inside GFW by %s'%self.adr
        try: html = requests.get('http://www.ip.cn', headers=getHeader(), proxies=self.proxy, timeout=3).text
        except Exception as e: return 0
        print 'Checking anonymity of %s'%self.adr
        # 第四重验证：检测该代理是否高匿
        resu = ''.join( re.findall('<code>([^<>]+)</code>', html) )
        if self.host not in resu: return 0
        # print 'My IP detected on the Internet is %s.'%resu
        print '---OK----%s'%self.uri
        return speed

    def ieProxy(self, op):
        if not op : return 'No assigned operation.'
        # 只有代理地址测试通过了才为本机设置IP
        if op == 'ProxyOnly':
            if not self.check(): return 'Proxy did not change because [%s] failed on test.'%self.uri
        def __toHex(obj):
            if   obj == '': return ''
            elif obj == 0 or obj == '0' or obj == '00': return '00'
            if isinstance(obj, str):
                return ','.join([ str(hex(ord(s))).replace('0x','') for s in obj ])
            elif isinstance(obj, int):
                num = str(hex(obj)).replace('0x', '')
                # 如果是一位数则自动补上0，7为07，e为0e
                return num if len(num)>1 else '0'+num
        options = {'On':'0F','Off':'01','ProxyOnly':'03','PacOnly':'05','ProxyAndPac':'07','D':'09','DIP':'0B','DS':'0D'}
        if op == 'Off': # 关闭所有代理设置
            reg_value = '46,00,00,00,00,00,00,00,01'
        else: # 根据选项设置代理
            switcher = options.get(op)
            if not switcher: return '---Unexpected Option.---'
            noLocal = False #"跳过本地地址的代理服务器"这项就默认不设置了
            skipLocal = '07,00,00,00,%s'%__toHex('<local>') if noLocal else '00'
            reg_value = '46,00,00,00,00,00,00,00,%(swi)s,00,00,00,%(ipLen)s,00,00,00,%(ip)s00,00,00,%(ski)s,21,00,00,00%(pac)s' % ({
                'swi':switcher,
                'ipLen':__toHex(len(self.adr)),
                'ip':__toHex(self.adr) + ',' if self.adr else '',
                'infoLen':__toHex(len('<local>')),
                'ski':skipLocal,
                'pac':','+__toHex(self.pac) if self.pac else ''
            })
        # print options[op] +'\n'+ __toHex(self.adr) +'\n'+ __toHex(self.pac) #调试用
        settings = 'Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections]\n"DefaultConnectionSettings"=hex:%s' % reg_value
        # print settings #调试用
        # === 生成reg文件并导入到注册表中 ===
        filePath = os.environ['TEMP'] + '\DefaultConnectionSettings.reg' #放到命令行的工作目录(可跨系统操作)
        with open(filePath, 'w') as f:
            f.write( settings )
        cmd = 'reg import "%s"' % filePath
        if len(os.popen(cmd).readlines()) > 1: return '---Failed on registering reg file.---'
        # 删除临时的.reg文件 (如果文件目录在临时文件夹中，就不用删了)
        # if os.path.exists(filePath): os.remove(filePath)
        return 'Successfully registered proxy settings.'


class ProxyPool():
    def __init__(self):
        self.lines = [] # 网上获取代理地址
        self.uris  = [] # 验证通过的代理地址
        self.online = True # 是否在线获取，否的话则为本地网页文件获取

    def getProxies(self):
        with open('proxyJungle.txt', 'r') as f:
            return [line for line in f.readlines() if Proxy(line).uri]

    def extractIP(self, site):
        # 选择是在线获取还是根据本地HTML文件获取
        if self.online:
            r = requests.get(site['url'], headers=getHeader(), timeout=3)
            content = r.text
        else:
            with open(site['loc'], 'r') as f: content = f.read()
        # 开始从HTML源码中进行内容抽取
        ptn = site.get('re') if site.get('re') else site.get('ptn')
        if site.get('re'): #一般获取方式
            resu = re.findall(ptn[0], content)
            if len(resu) < 1: return
            for m in resu:
                pto = 'https://' if 'https' in m[ptn[3]].lower() else 'http://'
                self.lines.append( pto + m[ptn[1]] +':'+ m[ptn[2]] )
        else: #特殊获取方式
            soup = BeautifulSoup(content, 'html5lib')
            if ptn[0] == 'goubanjia' or ptn[0] == 'qiaodm':
                rows = soup.select(ptn[1])
                for ro in rows:
                    port = ''.join([ ':'+t.get_text() for t in ro.select(ptn[2]) ])
                    pto = ''.join([ t.get_text() for t in ro.select(ptn[3]) ])
                    pto = 'https://' if 'https' in pto else 'http://'
                    chaos = re.findall( ptn[5], str(ro.select(ptn[4])) )
                    prx = ''.join( [c[2] for c in chaos if c])
                    mix = pto + prx + port
                    if mix: self.lines.append(mix)

    def update(self):
        # 定制所有抓取代理的网址及正则表达式
        sites  = []
        sites.append({'url': 'http://www.kuaidaili.com/free/outha/',
                      'loc':'proxyHTML/kuaidaili.com.html',
                      're': ['<td>(\d+\.\d+\.\d+\.\d+)</td>\s*<td>(\d+)</td>\s*<td>[^<>]*</td>\s*<td>([^<>]*)</td>', 0, 1, 2] })
        sites.append({'url': 'http://www.xicidaili.com/nn/',
                      'loc':'proxyHTML/xicidaili.com.html',
                      're': ['<td>(\d+\.\d+\.\d+\.\d+)</td>\s*<td>(\d+)</td>\s*<td>[^<>]*</td>\s*<td>[^<>]*</td>\s*<td>([^<>]*)</td>', 0,1,2]})
        # sites.append({'url': 'http://www.fengyunip.com/free/china-high.html',
        #               'loc':'proxyHTML/fengyunip.com.html',
        #               're': ['<td>(\d+\.\d+\.\d+\.\d+)</td>\s*<td>(\d+)</td>\s*<td>[^<>]*</td>\s*<td>[^<>]*</td>\s*<td>([^<>]*)</td>', 0,1,2]})
        def __checkIPs(prx):
            if Proxy(prx).check() > 0:
                self.uris.append(prx)
        multiThread(func=self.extractIP, prams=sites)
        print 'Retrived %d proxies, now start to test each of them.'%len(self.lines)
        # 开始检测有效性，只收录可用代理
        # uris = [i for i in self.lines if Proxy(i).check() > 0] # 单线程检测
        multiThread(func=__checkIPs, prams=self.lines) # 多线程检测
        print 'Got %d varified proxies.'%len(self.uris)
        with open('proxyJungle.txt', 'w') as f:
            f.write('\n'.join(self.uris))
        # print self.uris
        print '-----Stored %d proxies for this time.'%len(self.lines)

    # def update2(self, func):
        #

def getHeader():
    # 随机使用一个浏览身份
    agents = []
    agents.append('Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))') # IE
    agents.append('Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36') # Chrome
    agents.append('Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25') # Safari Mobile
    agents.append('Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30') # Android Webkit Browser
    agents.append('Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25') # Safari Mobile
    # if not ag.has_key('User-Agent'): ag['User-Agent'] = agents[ random.randint(0,len(agents)-1) ]
    ag = { 'User-Agent':agents[random.randint(0,len(agents)-1)] }
    return ag

def multiThread(func, prams):
    threadList = []
    for p in prams:
        t = Thread(target=func, args=(p,))
        t.start()
        threadList.append(t)
    print 'Now there are %d threads.'%len(threadList)
    for sub in threadList:
        sub.join()

# ---------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
