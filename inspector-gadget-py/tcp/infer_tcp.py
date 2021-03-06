from __future__ import with_statement
from __future__ import print_function

from socket import socket, AF_PACKET, SOCK_RAW, htons
from struct import *
import select
import time


from scapy.all import *
import random
import http as HTTP
import multiprocessing
import Queue
from datetime import datetime
import threading
import csv
import os
import math
from scapy_ssl_tls.ssl_tls import *

# try:
#	 # This import works from the project directory
#	 from scapy_ssl_tls.ssl_tls import *
# except ImportError:
#	 # If you installed this package via pip, you just need to execute this
#	 # from scapy.layers.ssl_tls import *
#	 print('Need to import from modified source.')
#	 sys.exit()



class TcpHandshake(object):
	def __init__(self, target):
		self.seq = random.randrange(100000,99999999)
		self.dst_ip = Net(target[0])
		self.dst_port = target[1]
		self.src_port = random.randrange(20000,50000)
		self.pkt = IP(dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, window=65535, flags=0, seq=self.seq, options=[("MSS",1460),("WScale",8),("NOP",None),("EOL",None)])
		# self.pkt = IP(dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, window=65535, flags=0, seq=self.seq, options=[])
		self.src_ip = self.pkt.src
		self.swin = self.pkt[TCP].window
		self.dwin=1
		print("init:",self.dst_ip,self.dst_port,self.src_ip,self.src_port)

	def send_syn1(self):
		print("sending SYN pkt.")
		self.pkt[TCP].flags = "S"
		res_pkt = sr1(self.pkt)
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
		self.pkt[TCP].ack = temp_pkt[TCP].seq + 1
		self.pkt[TCP].seq = temp_pkt[TCP].ack
		send(self.pkt) # no response for ack
		tcp_obj.pkt[TCP].ack = temp_pkt[TCP].seq + 1

def get_tcp_flag(i):
	return i.sprintf("%TCP.flags%")

def send_ack(tcp_obj, i, new_seq):
	newpkt = IP(dst=tcp_obj.dst_ip)/TCP(sport=tcp_obj.src_port, dport=tcp_obj.dst_port, window=65535, flags=0, options=[("NOP",None),("EOL",None)])
	newpkt[TCP].flags = "A"
	newpkt[TCP].ack = new_seq
	newpkt[TCP].seq = i
	send(newpkt) # no response for ack

def sniffer_simple(tcp_obj, src_port, dst_port, src_ip, dst_ip, tout, write_dir):
	# print("sniff thread started")
	# build_filter = lambda (r): TCP in r and (r[TCP].dport == src_port or r[TCP].sport == src_port)
	build_filter = lambda (r): TCP in r and (r[TCP].sport == 443)
	packets_sniffed = sniff(lfilter=build_filter, timeout=tout)

	for i in packets_sniffed:
		print(tcp_obj.seq)

		# if i[IP].src == dst_ip and i[IP].dst == src_ip:
		if True:
			
			fr = open('/home/usama/github/InspectorGadget/src/ig_v4/py-tcp/seq.txt', 'r')
			new_seq_num = int(fr.read())
			fr.close()

			pkt_len = i[IP].len - i[IP].ihl * 4 - i[TCP].dataofs * 4

			print('new_seq_num:', new_seq_num, '| pkt_len:', pkt_len)

			if pkt_len > 0 and i[TCP].dport == tcp_obj.src_port:
				send_ack(tcp_obj, new_seq_num, i[TCP].seq + pkt_len)


			'''
			tcp_flag = get_tcp_flag(i)

			print('*****************************************')
			print(i[TCP].payload.decode_payload_as)
			# print(binascii.hexlify(str.encode(i[TCP].payload)))
			print('*****************************************')

			# temp = hexdump(i[TCP].payload)
			hex_resp = ''
			# print(len(str(i[TCP].payload)))
			for b in str(i[TCP].payload):
				s = "%x"%(ord(b))
				if len(s) == 1:
					s = '0' + s
				hex_resp += s

			padding_flag = 0
			for j in hex_resp:
				if j != '0':
					padding_flag = 1
					break

			# if padding_flag == 1:
				# fw = open(write_dir + str(i[TCP].seq), 'w')
				# fw = open(write_dir + str(1), 'wb')
				# fw.write(str.encode(hex_resp))
				# fw.close()

				# send_ack(tcp_obj, tcp_obj.pkt[TCP].seq, i[TCP].seq + (len(hex_resp) / 2))
			'''

def worker(tcp_obj, src_port, dst_port, src_ip, dst_ip, tout, write_dir):
	for i in range(0, 10):
		sniffer_simple(tcp_obj, src_port, dst_port, src_ip, dst_ip, tout, write_dir)



WRITE_DIR_CONF = '/home/usama/github/inspector-gadget-py/conf/'

def dump_seq_ack(seq, ack):
    global WRITE_DIR_CONF
    if seq != -1:
        f = open(WRITE_DIR_CONF + 'seq.txt', 'w')
        f.write(str(seq))
        f.close()

    if ack != -1:
        f = open(WRITE_DIR_CONF + 'ack.txt', 'w')
        f.write(str(ack))
        f.close()

def read_seq_ack():
    global WRITE_DIR_CONF
    fr = open(WRITE_DIR_CONF + 'seq.txt', 'r')
    seq = int(fr.read())
    fr.close()

    fr = open(WRITE_DIR_CONF + 'ack.txt', 'r')
    ack = int(fr.read())
    fr.close()

    return [seq, ack]


if __name__ == "__main__":

	ETH_P_ALL = 3
	ETH_P_IP = 0x800  
	s = socket.socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
	s.bind(("wlp1s0", 0))

	# dst_name = "primus.cs.duke.edu"
	# dst_name = "www.facebook.com"
	dst_name = "www.google.com"

	dst_ip = socket.gethostbyname(dst_name)
	dst_port = 443
	emulated_rtt = 0.5
	mss = 64

	timeout_tls = 0.5
	timeout = 0.1
	prefix = "test"
	curr_dir = os.getcwd()
	if curr_dir[len(curr_dir) - 1] != '/':
		curr_dir += '/'

	ua_string = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36'
	req_obj = '/'

	# # STEP 1: TCP HNADSHAKE
	tcp_obj = TcpHandshake([dst_name,dst_port])
	res_pkt = tcp_obj.send_syn1()
	tcp_obj.pkt[TCP].options = [("NOP",None),("EOL",None)]
	
	tcp_obj.dst_ip = res_pkt[IP].src
	tcp_obj.pkt[IP].dst = res_pkt[IP].src
	time.sleep(emulated_rtt)
	tcp_obj.send_synack_ack(res_pkt)
	
	f = open(WRITE_DIR_CONF + 'conn-info.csv', 'w')
	cw = csv.writer(f)
	cw.writerow([tcp_obj.dst_ip, tcp_obj.src_port, tcp_obj.dst_port, emulated_rtt, mss, tcp_obj.pkt[TCP].seq, tcp_obj.pkt[TCP].ack])
	f.close()

	# dump_seq_ack(tcp_obj.pkt[TCP].seq, tcp_obj.pkt[TCP].ack)

	# t = multiprocessing.Process(target=worker, args=(tcp_obj, tcp_obj.src_port, tcp_obj.dst_port, tcp_obj.src_ip, tcp_obj.dst_ip, timeout, curr_dir + 'resp_pkts/',))
	# t.start()

	# TLS handshake
	tls_version = TLSVersion.TLS_1_2
	ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]
	extensions = [TLSExtension() / TLSExtECPointsFormat(),
				  TLSExtension() / TLSExtSupportedGroups()]

	# HOST = socket.gethostbyname(socket.gethostname())
	# sc1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	# sc1.bind((HOST, tcp_obj.src_port))

	target_ip_port = (dst_ip,dst_port)
	with TLSSocket(input_tcp_obj=tcp_obj, sock=s, client=True) as tls_socket:
		try:
			server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)

		except TLSProtocolError as tpe:
			print("Got TLS error: %s" % tpe, file=sys.stderr)

		else:
			resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: %s\r\n\r\n"%(dst_name)))
			print("Got response from server")
			resp.show()


	'''
	tls_version = TLSVersion.TLS_1_2
	ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]
	extensions = [TLSExtension() / TLSExtECPointsFormat(),
				  TLSExtension() / TLSExtSupportedGroups()]

	ip = (dst_ip, dst_port)
	with TLSSocket(client=True) as tls_socket:
		try:
			tls_socket.connect(ip)
			print("Connected to server: %s" % (ip,))
		except socket.timeout:
			print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
		else:
			try:
				server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
				# server_hello.show()
			except TLSProtocolError as tpe:
				print("Got TLS error: %s" % tpe, file=sys.stderr)
				# tpe.response.show()
			else:
				resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
				print("Got response from server")
				# resp.show()
			# finally:
			# 	print(tls_socket.tls_ctx)
	'''

				