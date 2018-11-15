from scapy.all import sr1, IP, TCP
import csv
from timeout import timeout
import os
import errno
import multiprocessing
import time

@timeout(5, os.strerror(errno.ETIMEDOUT))
def test_tfo(dst,dport):
        res = sr1(IP(dst=dst)/TCP(dport=dport,flags="S",options=[('TFO', '')]), verbose=False)
        if res is not None:
                return 'TFO' in dict(res[1].options)
        else:
                False

print test_tfo("www.how01.com",443)

