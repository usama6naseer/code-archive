import subprocess
from subprocess import Popen, PIPE
import csv
import os
import sys
import errno
import multiprocessing
import time
import signal
from scapy.all import *

WRITE_DIR_CONF = '/home/usama/github/inspector-gadget-py/conf/'

def read_seq_ack():
    global WRITE_DIR_CONF
    fr = open(WRITE_DIR_CONF + 'seq.txt', 'r')
    seq = int(fr.read())
    fr.close()

    fr = open(WRITE_DIR_CONF + 'ack.txt', 'r')
    ack = int(fr.read())
    fr.close()

    return [seq, ack]

def fin_connection():
	global WRITE_DIR_CONF

	print('Fin connection.')

	src_port = 0
	dst_ip = ''
	dst_port = 0

	try:
		cr = csv.reader(open(WRITE_DIR_CONF + 'conn-info.csv','r'))
		for row in cr:
			dst_ip = row[0]
			src_port = int(row[1])
			dst_port = int(row[2])
		
	except Exception as e:
		print('conn-info:', e)

	ret = read_seq_ack()

	print(src_port, dst_ip, dst_port, ret)

	ip = IP(dst=dst_ip)
	rst = TCP(sport=src_port, dport=dst_port, flags="R", seq=ret[0], ack=ret[1])
	send(ip/rst)

if __name__ == "__main__":
	fin_connection()







						
