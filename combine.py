#!/usr/bin/env python
__author__ = 'jwindsor'
__copyright__ = "Copyright 2015"
__credits__ = ["Josh Windsor"]
__license__ = "Josh Windsor"
__email__ = "ging.sor@gmail.com"
__status__ = "Prototype"

import os

def combineScans(scanFileDir):
    saveDir = os.getcwd()
    os.chdir(scanFileDir)
    files = os.listdir(scanFileDir)

    for file in files:
        scanFile = open(file, 'r')

        singleHostScan = scanFile.read()
        scanFile.close()

        if 'status state="down"' in singleHostScan:
            os.remove(os.path.join(scanFileDir, file))


def main():
    combineScans('/home/jwindsor/Code/Projects/PyNetMapper/home-net')

if __name__ == '__main__':
    main()
