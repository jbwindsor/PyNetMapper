#!/usr/bin/env python
__author__ = 'jwindsor'
__copyright__ = "Copyright 2015"
__credits__ = ["Josh Windsor"]
__license__ = "Josh Windsor"
__email__ = "ging.sor@gmail.com"
__status__ = "Prototype"

from libnmap.process import NmapProcess
from combine import combineScans
from threading import Thread
from Queue import Queue
import argparse
import netaddr
import logging
import os

class Worker(Thread):

    def __init__(self, tasks):
        super(Worker, self).__init__()
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()

            try:
                func(*args, **kargs)
            except Exception, e:
                print(e)
            finally:
                print("task done")
                self.tasks.task_done()

class ThreadPool:

    def __init__(self, numThreads):
        self.tasks = Queue(numThreads)
        for tp in range(numThreads):
           Worker(self.tasks)

    def addTask(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def wait(self):
        self.tasks.join()

def getScanRange(ipStr):
    scanRange = []
    if "-" in ipStr:
        print("[*] ip range")
        ipStart = ipStr.split("-")[0]
        lastOctect = ipStart.rfind(".")
        ipEnd = ipStart[0:lastOctect] + "." + ipStr.split("-")[1][0::]
        ipList = list(netaddr.iter_iprange(ipStart, ipEnd))
        for ip in ipList:
            scanRange.append(str(ip))
    elif "/" in ipStr:
        print("[*] cider")
        scanRange = []
        for ip in netaddr.IPNetwork(ipStr).iter_hosts():
            scanRange.append(str(ip))
    elif "," in ipStr:
        print("[*] ip list")
        scanRange = ipStr.split(",")
    else:
        scanRange.append(ipStr)

    return scanRange

def parseArgs():
    parser = argparse.ArgumentParser(description="Threaded Nmap Scanner")
    parser.add_argument('--scan-name', action="store", dest="scanName")
    parser.add_argument('--ip-range', action="store", dest="ipRange")
    parser.add_argument('--options', action="store", dest="options")

    return parser.parse_args()

def scanIp(ip, options, scandir='tmp'):
    #print("Scanning IP: {0}. Nmap options {1}".format(ip, options))
    nm = NmapProcess(ip, options=options, )
    rc = nm.run()

    if nm.rc == 0:
        if 'status state="down"' not in nm.stdout and \
                        'reason="host-unreach"' not in nm.stdout and \
                        'reason="net-unreaches"' not in nm.stdout:
            singleHostOut = os.path.join(scandir, ip + '.xml')
            scanFile = open(singleHostOut, 'w')
            scanFile.write(nm.stdout)
            scanFile.close()
        else:
            downHostsOut = os.path.join(scandir, 'down-hosts.txt')
            dHostsFile = open(downHostsOut, 'a')
            dHostsFile.write(ip + '\n')
            dHostsFile.close()

    else:
        print(nm.stderr)

def main():

    args = parseArgs()
    ipRange = getScanRange(args.ipRange)
    pool = ThreadPool(255)

    tmpScanfilesDir = os.path.join(os.getcwd(), args.scanName)
    try:
        os.mkdir(tmpScanfilesDir)
    except OSError, e:
        if e.errno == 17:
            pass
        else:
            print(e)

    for ip in ipRange:
        #options = "{0} -oX {1}/{2}.xml".format(args.options, tmpScanfilesDir, ip)
        options = "{0}".format(args.options)
        pool.addTask(scanIp, ip, options, scandir=tmpScanfilesDir)

    print("Waiting for join")
    pool.wait()
    print("Scan Complete")
    #combineScans(tmpScanfilesDir)

if __name__ == '__main__':
    main()
