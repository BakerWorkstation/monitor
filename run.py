#!/usr/bin/env python3.6
# -*- coding:utf-8 -*-
# __author__: sdc


import os
import sys
import uuid
import json
sys.path.append('./venv/Lib/site-packages')
import time
import sqlite3
from datetime import datetime
from config import app
from flask import render_template, Flask, request, redirect, url_for
import psutil
import socket
import platform

app = Flask(__name__,static_url_path='')
service_db = '/opt/monitor/services.db'
IP = socket.gethostbyname(socket.gethostname())

@app.route('/sys/')
def sys():
    now_time= datetime.now()  # 现在时间
    start_time=datetime.fromtimestamp(psutil.boot_time()) # 开机时间
    totalSecond = int((now_time - start_time).total_seconds())
    second = totalSecond % 60
    minute = int(totalSecond / 60 % 60)
    hour = int(totalSecond / 60 / 60 % 24)
    day = int(totalSecond / 60 / 60 / 24)
    systeminfo = os.popen('uname -r').read().strip().split('-')
    version = systeminfo[0].split('.')
    major = version[0]
    minor = version[1]
    micro = version[2]
    fixinfo = systeminfo[1].split('.')
    fix = fixinfo[0]
    num = fixinfo[1].replace('el', '')
    syss={
    'system':platform.system(), #操作系统
    'version': '主版本号%s 次版本号%s 修订版本号%s 此次版本第%s 次修改 enterprise linux %s' % (major, minor, micro, fix, num), #platform.version(), #系统版本号
    'architecture':platform.architecture()[0].replace('bit', u'位'), #位数
    #'machine':platform.machine(), #类型
    #'processor':platform.processor(), #处理器信息
    'run_time': "%s天 %s小时 %s分 %s秒" % (day, hour, minute, second)        #str(now_time-start_time).split('.')[0]  #运行时间
    }
    # run_time=datetime.datetime.fromtimestamp(now_time-start_time)   #运行时间
    #print(run_time)
    return render_template('sys.html',now_time=str(now_time).split('.')[0],start_time=start_time,
                           syss=syss)

@app.route('/cpu/')
def cpu():
    cpuinfo = psutil.cpu_times_percent()
    idle = cpuinfo.idle
    user = cpuinfo.user
    system = cpuinfo.system
    cpu_freq = psutil.cpu_freq()
    averageload_1 = os.popen("uptime").read().strip().split(':')[-1].split(",")[0]
    if int(idle) == 1:
        idle = 100
    cpu={
    'p_CPU':psutil.cpu_count(logical=False),
    'CPU':psutil.cpu_count(),
    'averageload_1': averageload_1,
    'user': '%s%%' % user,
    'system': '%s%%'% system,
    'idle': '%s%%' % idle,
    'nowfrequency': '%.2fHz' % cpu_freq.current,
    'minfrequency': '%.2fHz' % cpu_freq.min,
    'maxfrequency': '%.2fHz' % cpu_freq.max
    }
    return render_template('cpu.html',cpu=cpu)

@app.route('/ram/')
def ram():
    meminfo = psutil.virtual_memory()
    ram={
    'memmorySize':round(meminfo.total/(1024**3), 2),
    'available':round(meminfo.available/(1024**3), 2),
    'percent': meminfo.percent,
    'used':round(meminfo.used/(1024**3),2),
    'free':round(meminfo.free/(1024**3),2)
    }
    return render_template('ram.html',ram=ram)

@app.route('/disk/')
def disk():
    disks=psutil.disk_partitions()
    dataList = []
    for eachdisk in disks:
        mountpoint = eachdisk.mountpoint
        device = eachdisk.device
        fstype = eachdisk.fstype
        opts = eachdisk.opts
        cap = psutil.disk_usage(mountpoint)
        total = round(cap.total / 1024 / 1024 / 1024, 2)
        used = round(cap.used / 1024 / 1024 / 1024, 2)
        free = round(cap.free / 1024 / 1024 / 1024, 2)
        percent = cap.percent

        dataList.append({
                         "device": device,
                         "mountpoint": mountpoint,
                         "fstype": fstype,
                         "opts": opts,
                         "total": "%sG" % total,
                         "used": "%sG" % used,
                         "free": "%sG" % free,
                         "percent": "%s%%" % percent
        })

        #(device='/dev/sda2', mountpoint='/', fstype='ext4', opts='rw,relatime,data=ordered')
    return render_template('disk.html',disks=dataList)

@app.route('/process/')
def process():
    sql = 'select process_name, process_cmd, process_path from service;'
    conn = sqlite3.connect(service_db)
    cursor = conn.cursor()
    cursor.execute(sql)
    attList = []
    for row in cursor:
        name = row[0]
        cmd = row[1]
        path = row[2]
        attList.append({'name': name, 'cmd': cmd, 'path': path, 'hit': False})
    conn.close()
    pid=psutil.pids()#[:20]
    processes=[]
    for i in pid:
        flag = False
        process_color = 'white'
        process_attstatus = 0
        try:
            p=psutil.Process(i)
            #print(p.exe())
            process_name = p.name()
            process_pid = p.pid
            if process_pid < 300:
                continue
            process_cmd = ' '.join(p.cmdline())
            process_path = p.cwd()
            process_status = p.status()
            process_ctime = datetime.fromtimestamp(p.create_time())
            process_mempercert = round(p.memory_percent(), 2)
            for eachAtt in attList:
                att_name = eachAtt["name"]
                att_cmd = eachAtt["cmd"]
                att_path = eachAtt["path"]
                if process_name.strip() == att_name.strip() and process_cmd.strip() == att_cmd.strip() and process_path.strip() == att_path.strip():
                    process_attstatus = 1
                    eachAtt["hit"] = True
                    flag = True
                    break
            processData = (process_name, process_pid, process_cmd, process_path, process_status, process_ctime, process_mempercert, process_attstatus, process_color, )
            if flag:
                processes.insert(0, processData)
            else:
                processes.append(processData)
        except:
            continue
    for eachatt in attList:
        if not eachatt["hit"]:
            processes.insert(0, (eachatt["name"], "", eachatt["cmd"], eachatt["path"], "", "", "", 1, "red"))
    return render_template('process.html',processes=processes)


@app.route('/process/attention/add', methods=['POST'])
def add():
    request_data  = request.get_data()
    name = request.form["name"]
    cmd = request.form["cmd"]
    path = request.form["path"]
    conn = sqlite3.connect(service_db)
    cursor = conn.cursor()
    sql = 'insert into service(id, process_name, process_cmd, process_path, dev_ip, r_time) values(?, ?, ?, ?, ?, ?);'
    sid = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uuid.uuid1()))).replace("-", "").upper()
    r_time = int(time.time())
    args = (sid, name, cmd, path, IP, r_time,)
    cursor.execute(sql, args)
    conn.commit()
    conn.close()
    #return redirect(url_for('process'))
    return json.dumps({"message": "ok"})

@app.route('/process/attention/del', methods=['POST'])
def delete():
    request_data  = request.get_data()
    name = request.form["name"]
    cmd = request.form["cmd"]
    path = request.form["path"]
    conn = sqlite3.connect(service_db)
    cursor = conn.cursor()
    sql = 'delete from service where process_name= ? and process_cmd=? and process_path=? ;'
    args = (name, cmd, path, )
    cursor.execute(sql, args)
    conn.commit()
    conn.close()
    return json.dumps({"message": "ok"})


if __name__ == '__main__':
    app.run('0.0.0.0', 5000, ssl_context=('./ca/server.crt', './ca/server.key'))
