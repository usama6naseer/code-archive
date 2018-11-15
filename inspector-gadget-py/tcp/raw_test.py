# from __future__ import with_statement
# from __future__ import print_function

from socket import socket, AF_PACKET, SOCK_RAW, htons
from struct import *
import select
import time

from scapy.all import *

class TcpHandshake(object):
   def __init__(self, target):
      self.seq = random.randrange(0,2**32)
      self.seq_next = 0
      self.dst_ip = Net(target[0])
      self.dst_port = target[1]
      self.src_port = random.randrange(20000,65000)
      self.pkt = IP(dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, window=65535, flags=0, seq=self.seq, options=[("MSS",1460),('WScale', 8)])
      self.src_ip = self.pkt.src
      self.swin = self.pkt[TCP].window
      self.dwin=1
      print("init:",self.dst_ip,self.dst_port,self.src_ip,self.src_port)

   def send_syn_dontwait(self):
      print("sending SYN pkt. wont wait for reply.")
      self.pkt[TCP].flags = "S"
      send(self.pkt)

# https://stackoverflow.com/questions/4534438/typeerror-module-object-is-not-callable

def filter_right_pkt(in_pkt, src_ip, src_port):
   temp = Ether(message)
   if temp.haslayer(TCP):
      hexdump(in_pkt)
      print(temp[TCP].sport, temp[TCP].dport)
      # print(temp.summary())
      # print(temp.show())
      # print(temp[TCP].load)
      return 1


   return 0


if __name__ == "__main__":
   

   ETH_P_ALL = 3
   ETH_P_IP = 0x800  
   s = socket.socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
   s.bind(("wlp1s0", 0))

   tcp_obj = TcpHandshake(['www.google.com', 80])
   res_pkt = tcp_obj.send_syn_dontwait()

   while True:

      message = s.recv(4096)

      # print(message)

      ret = filter_right_pkt(message, tcp_obj.src_ip, tcp_obj.src_port)
      if ret == 1:
         break
      