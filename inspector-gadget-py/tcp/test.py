from __future__ import with_statement
from __future__ import print_function

from scapy.all import *
import random
import http as HTTP
import multiprocessing
import Queue
from datetime import datetime
import threading
import csv
import os
import socket
import math
from scapy_ssl_tls.ssl_tls import *

# try:
#     # This import works from the project directory
#     from scapy_ssl_tls.ssl_tls import *
# except ImportError:
#     # If you installed this package via pip, you just need to execute this
#     # from scapy.layers.ssl_tls import *
#     print('Need to import from modified source.')
#     sys.exit()


class TcpHandshake(object):
	def __init__(self, target):
		self.seq = 0
		self.seq_next = 0
		self.dst_ip = Net(target[0])
		self.dst_port = target[1]
		self.src_port = random.randrange(2000,65000)
		self.pkt = IP(dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, window=65535, flags=0, seq=random.randrange(0,2**32), options=[("MSS",1460),('WScale', 8)])
		self.src_ip = self.pkt.src
		self.swin = self.pkt[TCP].window
		self.dwin=1
		print("init:",self.dst_ip,self.dst_port,self.src_ip,self.src_port)

	def send_syn1(self):
		print("sending SYN pkt.")
		self.pkt[TCP].flags = "S"
		res_pkt = sr1(self.pkt)
		return res_pkt

	def send_syn(self):
		print("sending SYN pkt.")
		self.pkt[TCP].flags = "S"
		res_pkt = sr(self.pkt)
		return res_pkt

	def send_syn_dontwait(self):
		print("sending SYN pkt. wont wait for reply.")
		self.pkt[TCP].flags = "S"
		send(self.pkt)

	def send_rst(self, seq_new, ack_new):
		print("sending RST pkt.")
		self.pkt[TCP].flags = "R"
		self.pkt[TCP].ack = seq_new + 1
		self.pkt[TCP].seq = ack_new
		send(self.pkt)

	def send_synack_ack(self, temp_pkt):
		print("sending ACK after SYN/ACK")
		self.pkt[TCP].flags = "A"
		self.pkt[TCP].ack = temp_pkt[TCP].seq+1
		self.pkt[TCP].seq = temp_pkt[TCP].ack
		send(self.pkt) # no response for ack


if __name__ == "__main__":
	'''
	dst_name = "primus.cs.duke.edu"
	dst_ip = socket.gethostbyname(dst_name)
	dst_port = 80
	timeout_tls = 0.5
	timeout = 0.8
	prefix = "test"
	curr_dir = os.getcwd()
	if curr_dir[len(curr_dir) - 1] != '/':
		curr_dir += '/'

	ua_string = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36'
	req_obj = '/'

	# STEP 1: TCP HNADSHAKE
	tcp_obj = TcpHandshake([dst_name,dst_port])
	res_pkt = tcp_obj.send_syn()

	# print(res_pkt, len(res_pkt))

	for i in res_pkt[0]:
		# print(i[0][TCP].seq, str(i[0]).encode("HEX"))
		# print(i[1][TCP].seq, str(i[1]).encode())
		# print(i[0][TCP].seq, i[0].command())
		# print(i[1][TCP].seq, i[1].command())
		hexdump(i[1])
		print(raw(i[1]))


	# tcp_obj.send_synack_ack(res_pkt)
	'''

	f = open('/home/usama/github/InspectorGadget/src/ig_v4/py-tcp/resp_pkts/1', 'rb')
	data = f.read()
	f.close()

	print(data)

