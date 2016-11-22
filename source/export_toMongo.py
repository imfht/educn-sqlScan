#coding:utf-8
import pymongo
import os
files = os.listdir('../站点序列/')
connect = pymongo.MongoClient('localhost')['edu_cns']['things']
for file in files:
#    print file.strip('subDomains.txt')
    connect.insert_one({'subDomains':[i.strip() for i in open('../站点序列/%s'%file).readlines()],'host':file})
