from scapy.all import *
import random
import http as HTTP
import multiprocessing
import Queue
from datetime import datetime
import threading
import csv

class TcpHandshake(object):
	def __init__(self, target):
		self.seq = 0
		self.seq_next = 0
		self.dst_ip = Net(target[0])
		self.dst_port = target[1]
		self.src_port = random.randrange(10000,20000)
		self.pkt = IP(dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, window=65535, flags=0, seq=random.randrange(0,2**32), options=[("MSS",1460),('WScale', 6)])
		self.src_ip = self.pkt.src
		self.swin = self.pkt[TCP].window
		self.dwin=1
		print("init:",self.dst_ip,self.dst_port,self.src_ip,self.src_port)

	def send_syn(self):
		print("sending SYN pkt")
		self.pkt[TCP].flags = "S"
		print(self.pkt[TCP].seq, self.pkt[TCP].ack)
		res_pkt = sr1(self.pkt)
		print(self.pkt[TCP].seq, self.pkt[TCP].ack)
		print(res_pkt[TCP].seq, res_pkt[TCP].ack)
		# self.pkt[TCP].seq += 1
		# res_pkt.show()
		return res_pkt

	def send_synack_ack(self, temp_pkt):
		print("sending ACK pkt after getting SYN/ACK")
		print("packet ACKed is ",temp_pkt[TCP].seq+1)
		self.pkt[TCP].flags = "A"
		self.pkt[TCP].ack = temp_pkt[TCP].seq+1
		self.pkt[TCP].seq = temp_pkt[TCP].ack
		print(self.pkt[TCP].seq, self.pkt[TCP].ack)
		res_pkt = send(self.pkt) # no response for ack
		print(self.pkt[TCP].seq, self.pkt[TCP].ack)
		return res_pkt

	def receive_pkt(self, res_pkt):
		if res_pkt and res_pkt.haslayer(IP) and res_pkt.haslayer(TCP):
			if res_pkt[TCP].flags & 0x3f == 0x12:   # SYN+ACK
				print("RCV: SYN+ACK")
				new_res_pkt = self.send_synack_ack(res_pkt)
				print("********* received *********")
				self.receive_pkt(new_res_pkt)
			
			elif  res_pkt[TCP].flags & 4 != 0:      # RST
				print("RCV: RST")
			
			elif res_pkt[TCP].flags & 0x1 == 1:     # FIN
				print("RCV: FIN")
			
			elif res_pkt[TCP].flags & 0x3f == 0x10: # FIN+ACK
				print("RCV: FIN+ACK")

def sniffer_rto(port,host_ip,tout,qu_rto,qu_rwin):
	build_lfilter = lambda (r): TCP in r and r[TCP].dport == port and r[IP].src == host_ip
	p = sniff(lfilter=build_lfilter, timeout=tout)
	seen_time = []
	for i in p:
		print(len(i[TCP]),i[TCP].seq,i[TCP].ack,i[TCP].seq+len(i[TCP])-20,i.time)
		print('window:',i[TCP].window)
		qu_rwin.put(i[TCP].window)
		seen_time.append(i.time)
	for i in seen_time:
		print(i)
		qu_rto.put(i)

def operation(dst_ip):
	try:
		try:
			dst_ip_ip = socket.gethostbyname(dst_ip)
			print(dst_ip_ip)
			dst_port = 443
			timeout = 10
			prefix = "test"

			tcp_obj = TcpHandshake([dst_ip,dst_port])
			# print("seq",tcp_obj.pkt[TCP].seq)

			qu_rto = Queue.Queue()
			qu_rwin = Queue.Queue()
			t = threading.Thread(target=sniffer_rto, args=(tcp_obj.src_port,dst_ip_ip,7,qu_rto,qu_rwin,))
			t.start()
			print("sniff thread started")

			res_pkt = tcp_obj.send_syn()

			rwin_val = -1
			a2 = 0
			a1 = 0 

			t.join(8)
			if qu_rwin.qsize() > 0:
				rwin_val = qu_rwin.get()
				print('rwin:',rwin_val)
			if qu_rto.qsize() > 1:
				a1 = qu_rto.get()
				a2 = qu_rto.get()
				print('rto:',a2-a1)

			fw = open('rto-rwin.csv','a')
			cw = csv.writer(fw)
			cw.writerow([dst_ip,rwin_val,a2-a1])
			fw.close()
		except Exception,e:
			fw = open('rto-rwin.csv','a')
			cw = csv.writer(fw)
			cw.writerow([dst_ip,-1,-1])
			fw.close()
			print(row,e)
			pass
	except Exception,e:
		fw = open('rto-rwin.csv','a')
		cw = csv.writer(fw)
		cw.writerow([dst_ip,-1,-1])
		fw.close()
		print(row,e)
		pass


		
if __name__ == "__main__":
	f = open('top-1m.csv')
	c = csv.reader(f)
	for row in c:
		try:
			if int(row[0]) >= 0:
				if int(row[0]) > 10000:
					break
				dst_ip = 'www.'+str(row[1]).strip()

				# dst_ip = row[0]
				print(dst_ip)
				t = threading.Thread(target=operation, args=(dst_ip,))
				t.start()
				t.join(9)
				# dst_ip = 'www.google.com'
				# dst_ip = "magnus.cs.duke.edu"
				# dst_ip = "www.espnfc.us"
				# dst_ip = "www.facebook.com"
				# dst_ip = 'www.reddit.com'
				# dst_ip = '54.152.215.137'
		except Exception,e:
			print(row,e)
			pass

			
