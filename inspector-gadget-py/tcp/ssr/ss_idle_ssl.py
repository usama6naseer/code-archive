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
import subprocess
from subprocess import Popen, PIPE
import urllib2

try:
    # This import works from the project directory
    # from scapy_ssl_tls.ssl_tls import *
    from scapy_orig_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    # from scapy.layers.ssl_tls import *
    print("NOT IMPORTED")

class TcpHandshake(object):
    def __init__(self, target):
        self.seq = 0
        self.seq_next = 0
        self.dst_ip = Net(target[0])
        self.dst_port = target[1]
        self.src_port = random.randrange(10000,20000)
        self.pkt = IP(dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, window=65535, flags=0, seq=random.randrange(0,2**32), options=[("MSS",1460),('WScale', 3)])
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

class SSThresh(object):
    def __init__(self, s1, s2, s3):
        self.ss_thresh = s1
        self.ss_found_flag = s2
        self.timeout_ack = s3
        self.after_found_count = 0
        self.dup_ack_count = 3
        self.timed_out = 0
        self.ss_found_but_continue = 0
        self.after_timeout_ack = 0
        self.after_timeout_ack_factor = 3

    def set_ss_thresh(self,a1):
        self.ss_thresh = a1

    def get_ss_thresh(self):
        return self.ss_thresh

    def set_found_flag(self,a1):
        self.ss_found_flag = 1

    def is_ss_found(self):
        return self.ss_found_flag

    def get_after_found_count(self):
        return self.after_found_count

    def set_after_found_count(self,a1):
        self.after_found_count = a1

    def decrement_after_found_count(self):
        if self.after_found_count > 0:
            self.after_found_count = self.after_found_count - 1
        if self.after_found_count == 0:
            return 0
        else:
            return self.after_found_count

    def decrement_dup_ack_count(self):
        if self.dup_ack_count > 0: 
            self.dup_ack_count = self.dup_ack_count - 1
        if self.dup_ack_count == 0:
            return 0
        else:
            return self.dup_ack_count

    def has_timedout(self):
        return self.timed_out

    def set_timeout_ack(self,a1):
        self.timeout_ack = a1

    def get_timeout_ack(self):
        return self.timeout_ack

    
def custom_listener_v1(packet):
    print("custom_listener: ",packet[TCP].seq,packet[TCP].ack,packet[IP].src,packet[IP].dst,len(packet),len(packet[TCP]),packet[TCP].seq+len(packet[TCP])-20,packet.time)

def header_reader(dst_ip,curr_dir,pkt,qu_header,qu_redirect):
    # print('header_reader')
    h = str(pkt[TCP])
    # print(h)
    server = -1
    length = -1
    timeout = -1
    maxc = -1
    print("&&&&&&&&&&&&&&&&&&&&&&&&")
    print(h)
    print("&&&&&&&&&&&&&&&&&&&&&&&&")
    if 'HTTP' in h:
        if '200 OK' in h:
            vec = h.split('\n')
            for i in vec:
                if 'Server' in i:
                    server = i.split(':')[1]
                elif 'Content-Length' in i:
                    length = i.split(':')[1]
                    length = int(length.strip())
                elif 'Keep-Alive' in i:
                    vec1 = i.split(',')
                    try:
                        if 'timeout' in vec1[0]:
                            timeout = vec1[0].split('=')[1]
                            timeout = int(timeout.strip())
                    except:
                        pass

                    try:
                        if 'max' in vec1[1]:
                            maxc = vec1[1].split('=')[1]
                            maxc = maxc.split('\\')[0]
                    except:
                        pass
                    break
            qu_header.put(length)
            qu_header.put(timeout)
            f = open(curr_dir+'/header_info.csv','a')
            c = csv.writer(f)
            c.writerow([dst_ip,server,length,timeout,maxc])
            f.close()
            print("header info:",[server,length,timeout,maxc])
        elif '302 Found' in h:
            vec = h.split('\n')
            for i in vec:
                if 'Location' in i:
                    redirect = i.split(':')[1]
                    redirect = redirect.strip()
                    redirect = redirect.replace('\r','')
                    redirect = redirect.replace('\n','')
                    # print("************************************",redirect)
                    qu_redirect.put(redirect)
                    break

def sniffer_for_tls(curr_dir,tcp_obj,tout,qu_pkt_counter,qu_pkt_length,qu_ack,qu_seq,qu_num_acks_out,qu_window,qu_header,qu_redirect):
# def sniffer_for_tls(curr_dir,tcp_obj,tout,qu_pkt_counter,qu_ack,qu_seq,qu_num_acks_out,qu_window):
    # build_lfilter = lambda (r): TCP in r and (r[TCP].dport == tcp_obj.src_port or r[TCP].dport == tcp_obj.dst_port) and (r[IP].src == tcp_obj.src_ip or tcp_obj.dst_ip)
    build_lfilter = lambda (r): TCP in r and (r[TCP].dport == tcp_obj.dst_port or r[TCP].sport == tcp_obj.dst_port) and (r[IP].src == tcp_obj.src_ip or r[IP].src == tcp_obj.dst_ip)
    p = sniff(lfilter=build_lfilter, timeout=tout)
    seq_tracker = {} # see if any pkt has been sent twice due to timeout
    packet_counter = 0
    packet_length = 0
    flag_window_found = 0
    for i in p:
    	# get window in tcp headers of first packet
    	if flag_window_found == 0 and i[IP].dst == tcp_obj.src_ip:
    		qu_window.put(i[TCP].window)
    		flag_window_found = 1
    		
        # print('&&&&&&&&&&&&&&&&')
        # print(len(i),len(i[TCP]),'seq num:',i[TCP].seq,'ack num:',i[TCP].ack,'next:',i[TCP].seq+len(i[TCP])-20,i[TCP].dport)
        # print(i[IP].dst,tcp_obj.dst_ip,i[TCP].flags,i[TCP].dataofs)
        # print(len(i),len(i[IP]),len(i[TCP]))
        # print('&&&&&&&&&&&&&&&&')

        if i[IP].dst == tcp_obj.dst_ip and i[TCP].flags == 16 and len(i) < 80:
            qu_num_acks_out.put(1)
        # if i[TCP].flags == 16: # ACK
            qu_ack.put(i[TCP].ack)
            qu_seq.put(i[TCP].seq)
        # elif len(i[TCP]) > 26 and i[IP].dst == tcp_obj.dst_ip and i[TCP].flags != 16:
        tcp_pkt_len = 4 * i[TCP].dataofs

        if len(i[TCP]) > tcp_pkt_len and i[IP].dst == tcp_obj.src_ip:
            if i[TCP].seq not in seq_tracker:
                print(len(i),len(i[TCP]),'seq num:',i[TCP].seq,'ack num:',i[TCP].ack,'next:',i[TCP].seq+len(i[TCP])-20,i[TCP].dport)
                packet_length = packet_length + len(i[TCP]) - tcp_pkt_len
                if len(i[TCP]) <= 1470:
                    packet_counter += 1
                else:
                    packet_counter = packet_counter + math.ceil(float(len(i[TCP]))/1460.0)
                seq_tracker[i[TCP].seq] = 1

                # t = threading.Thread(target=header_reader, args=(tcp_obj.dst_ip,curr_dir,i,qu_header,qu_redirect,))
                # t.start()
        
    qu_pkt_counter.put(packet_counter)
    qu_pkt_length.put(float(packet_length)/1460.0)
    print("packet count:",packet_counter)

def send_ack(tcp_obj,i,new_seq):
    newpkt = IP(dst=tcp_obj.dst_ip)/TCP(sport=tcp_obj.src_port, dport=tcp_obj.dst_port, window=65535, flags=0, options=[("MSS",1460)])
    newpkt[TCP].flags = "A"
    newpkt[TCP].ack = new_seq
    newpkt[TCP].seq = i
    send(newpkt) # no response for ack
    print('ack lenght:',len(newpkt))

def find_multiplier(q1,q2,ind):
    # if q2 == q1 * 2.0:
    if q2 == q1 * 2.0 or (q2 > q1*2.0*0.9 and q2 < q1*2.0*1.9):
        return 2 # for doubling the window
    # elif q2 == q1 ** 2.0:
    #   return 3 # for squaring the window
    # elif q2 == q1 ** 3.0:
    #   return 3 # for cubing the window
    else:
        return -1

def sniffer(port,host_ip,tout,qu_cwnd,tcp_obj,qu_ack):
    build_lfilter = lambda (r): TCP in r and r[TCP].dport == port and r[IP].src == host_ip
    # sniff(prn=custom_listener_v1, lfilter=build_lfilter, timeout=tout)
    p = sniff(lfilter=build_lfilter, timeout=tout)
    seen_seq_plus_len = [] # to be used for sending ACKs
    seen_len = [] # to be used for CWND calculation
    temp_ack = []
    seq_tracker = {} # see if any pkt has been sent twice due to timeout
    for i in p:
        # print(len(i[TCP]),i[TCP].seq,i[TCP].ack,i[TCP].seq+len(i[TCP])-20)
        tcp_pkt_len = 4 * i[TCP].dataofs
        # print(i[TCP])
        if len(i[TCP]) > 26:
            if i[TCP].seq not in seq_tracker:
                seq_tracker[i[TCP].seq] = 1
                # seen_seq_plus_len.append(i[TCP].seq+len(i[TCP])-20)
                seen_seq_plus_len.append(i[TCP].seq+len(i[TCP])-tcp_pkt_len)
                seen_len.append(len(i[TCP])-tcp_pkt_len)
                temp_ack.append(i[TCP].ack)
            else:
                repeat = 1
            # t = threading.Thread(target=header_reader, args=(i,qu_header,))
            # t.start()

    if len(seen_seq_plus_len) > 0:
        print("ENTERING ACK MODULE")
        # sending back ACKs
        temp = max(seen_seq_plus_len)
        print("SENDING ACK FOR",str(temp))
        t = threading.Thread(target=send_ack, args=(tcp_obj,max(temp_ack),temp,))
        t.start()
        qu_ack.put(temp)

        cwnd = round(sum(seen_len)/1460)
        qu_cwnd.put(cwnd)
        print("CWND:",cwnd)
    else:
        qu_cwnd.put(-1)
        qu_ack.put(-1)
        print("CWND:",-1)
def install_iptable_rule(src_port):
    # sudo iptables -A OUTPUT -p tcp --sport %s --tcp-flags FIN FIN -j DROP
    cm = ['sudo', 'iptables', '-A','OUTPUT','-p','tcp','--sport',str(src_port),'--tcp-flags','FIN','FIN','-j','DROP']
    process = Popen(cm, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    print("install iptable rule:",stdout,stderr)

def delete_iptable_rule():
    # sudo iptables -D OUTPUT 2
    cm = ['sudo', 'iptables', '-D','OUTPUT','2']
    process = Popen(cm, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    print("delete iptable rule:",stdout,stderr)

def operation(dst_name,clen):
    try:
        try:
            dst_ip = socket.gethostbyname(dst_name)
            dst_port = 443
            timeout_tls = 2
            timeout = 0.8
            prefix = "test"
            curr_dir = os.getcwd()

            ua_string = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36'
            req_obj = '/'
            # req_obj = '/about/main/gender-equality-films/'
            # req_obj = '/~tbenson/egypt'
            ini_pkt_in_tls = 0
            ini_pkt_in_length_tls = 0
            ini_ack_out_tls = 0
            ini_cwnd = 0
            ini_pkt_count = 0
            flag_cwnd_found = 0
            input_custom_timeout_window = 300.0
            custom_timeout_window = input_custom_timeout_window / 2.0
            ss_thresh_obj = SSThresh(0,0,0)
            cwnd_record = []

            # STEP 1: TCP HNADSHAKE
            tcp_obj = TcpHandshake([dst_name,dst_port])
            install_iptable_rule(tcp_obj.src_port)
            time.sleep(1)

            # print("seq",tcp_obj.pkt[TCP].seq)
            # res_pkt = tcp_obj.send_syn() # SYN
            # tcp_obj.receive_pkt(res_pkt) # ACK of SYN/ACK



            qu_pkt_counter_tls = Queue.Queue()
            qu_pkt_length_tls = Queue.Queue()
            qu_ack = Queue.Queue()
            qu_seq = Queue.Queue()
            qu_num_acks_out = Queue.Queue()
            qu_window = Queue.Queue()
            qu_header = Queue.Queue()
            qu_redirect = Queue.Queue()
            t = threading.Thread(target=sniffer_for_tls, args=(curr_dir,tcp_obj,timeout_tls,qu_pkt_counter_tls,qu_pkt_length_tls,qu_ack,qu_seq,qu_num_acks_out,qu_window,qu_header,qu_redirect,))
            # t = threading.Thread(target=sniffer_for_tls, args=(curr_dir,tcp_obj,timeout_tls,qu_pkt_counter_tls,qu_ack,qu_seq,qu_num_acks_out,qu_window,))
            t.start()
            print("Sniff thread started for TCP and SSL/TLS handshake")

            # TLS handshake
            tls_version = TLSVersion.TLS_1_2
            ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]
            extensions = [TLSExtension() / TLSExtECPointsFormat(),
                          TLSExtension() / TLSExtSupportedGroups()]
            
            target_ip_port = (dst_ip,dst_port)
            # with TLSSocket(input_tcp_obj=tcp_obj,client=True) as tls_socket:
            sc1 = socket.socket()
            with TLSSocket(sock=sc1,client=True) as tls_socket:
                tls_socket.bind(('',tcp_obj.src_port))
                # install_iptable_rule(tcp_obj.src_port)  
                try:
                    tls_socket.connect(target_ip_port)
                    print("Connected to server: %s" % (target_ip_port,))
                except socket.timeout:
                    print("Failed to open connection to server: %s" % (target_ip_port,), file=sys.stderr)
                
                try:
                    server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
                    # tls_socket._s.shutdown(1)
                    # tls_socket.close()
                except TLSProtocolError as tpe:
                    print("Got TLS error: %s" % tpe, file=sys.stderr)
                
                t.join()
                try:
                    tls_socket._s.close()
                except:
                    pass
                try:
                    sc1.close()
                except:
                    pass
                time.sleep(1)
                print("TLS socket closed")
                # print(qu_pkt_counter_tls.qsize())
                # print(qu_ack.qsize())
                # print(qu_seq.qsize())
                # print(qu_num_acks_out.qsize())
                # print(qu_window.qsize())

                
                if qu_pkt_counter_tls.qsize() > 0:
                    ini_pkt_in_tls = qu_pkt_counter_tls.get() 
                    print('qu_pkt_counter_tls:',ini_pkt_in_tls)
                else:
                    print('qu_pkt_counter_tls:',0)

                if qu_num_acks_out.qsize() > 0:
                    ini_ack_out_tls = qu_num_acks_out.qsize()
                    print('qu_num_acks_out:',ini_ack_out_tls)
                else:
                    print('qu_num_acks_out:',0)

                if qu_pkt_length_tls.qsize() > 0:
                    ini_pkt_in_length_tls = qu_pkt_length_tls.get()
                
                

                print("Sending GET request")
                tcp_obj.pkt[TCP].flags = "PA"            
                req = 'GET %s HTTP/1.1\r\nUser-Agent: %s\r\nAccept: */*\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n'%(req_obj,ua_string,dst_name)
                req_new = TLSPlaintext(data=req)

                if tls_socket.ctx.must_encrypt:
                    pkt_to_be_sent = str(tls_to_raw(req_new, tls_socket.tls_ctx, True, tls_socket.compress_hook, tls_socket.pre_encrypt_hook, tls_socket.encrypt_hook))
                else:
                    pkt_to_be_sent = str(req_new)
                        
                tcp_obj.pkt[TCP].ack = qu_ack.queue[qu_ack.qsize()-1]
                tcp_obj.pkt[TCP].seq = qu_seq.queue[qu_seq.qsize()-1]

                # qu_cwnd = Queue.Queue()
                # qu_header = Queue.Queue()
                # qu_redirect = Queue.Queue()
                # qu_pkt_counter = Queue.Queue()
                # t = threading.Thread(target=sniffer, args=(curr_dir,tcp_obj,dst_ip,timeout,qu_cwnd,qu_header,qu_redirect,qu_pkt_counter,ss_thresh_obj,custom_timeout_window,))
                # t.start()
                cwnd_obs = []
                tt = 2
                ack_new = -1

                qu_cwnd = Queue.Queue()
                qu_ack = Queue.Queue()
                t = threading.Thread(target=sniffer, args=(tcp_obj.src_port,dst_ip,timeout,qu_cwnd,tcp_obj,qu_ack,))
                t.start()
                print("sniff thread started")

                send(tcp_obj.pkt/pkt_to_be_sent)
                tcp_obj.pkt[TCP].seq += len(pkt_to_be_sent)

                tls_socket.tls_ctx.insert(req_new, tls_socket._get_pkt_origin('out')) # called in sendall

                for_times = 100
                total_len = 0
                for i in range(0,for_times):
                    t.join()
                    print("sniff thread joined")

                    total_len = total_len + 1460.0 * qu_cwnd.queue[qu_cwnd.qsize()-1]
                    print("**************** TOTAL LEN:",total_len,clen,qu_cwnd.queue[qu_cwnd.qsize()-1])
                    # if total_len > clen:
                    #     break
                    if qu_cwnd.queue[qu_cwnd.qsize()-1] == -1:
                        break

                    # qu_ack = Queue.Queue()
                    t = threading.Thread(target=sniffer, args=(tcp_obj.src_port,dst_ip,timeout,qu_cwnd,tcp_obj,qu_ack,))
                    t.start()
                t.join()                    
                print("Got response from server")
                c1 = qu_cwnd.get()
                print("observed cwnd:",c1)
                cwnd_obs.append(c1)

                print("WAIT FOR SECONDS:",tt)
                time.sleep(tt)
                tt=tt+2

                if qu_ack.qsize() > 0:
                    for j in range(0,qu_ack.qsize()):
                        temp_ack_new = qu_ack.queue[qu_ack.qsize()-1-j]
                        if  temp_ack_new != -1:
                            ack_new = temp_ack_new
                            break
                    print("ACK NEW",ack_new)

                if tls_socket.ctx.must_encrypt:
                    pkt_to_be_sent = str(tls_to_raw(req_new, tls_socket.tls_ctx, True, tls_socket.compress_hook, tls_socket.pre_encrypt_hook, tls_socket.encrypt_hook))
                else:
                    pkt_to_be_sent = str(req_new)
                

                qu_cwnd = Queue.Queue()
                qu_ack = Queue.Queue()
                t = threading.Thread(target=sniffer, args=(tcp_obj.src_port,dst_ip,timeout,qu_cwnd,tcp_obj,qu_ack,))
                t.start()
                print("sniff thread started")

                tcp_obj.pkt[TCP].ack = ack_new
                send(tcp_obj.pkt/pkt_to_be_sent)
                tcp_obj.pkt[TCP].seq += len(pkt_to_be_sent)

                tls_socket.tls_ctx.insert(req_new, tls_socket._get_pkt_origin('out')) # called in sendall

                for_times = 100
                total_len = 0
                for i in range(0,for_times):
                    t.join()
                    print("sniff thread joined")

                    total_len = total_len + 1460.0 * qu_cwnd.queue[qu_cwnd.qsize()-1]
                    print("**************** TOTAL LEN:",total_len,clen)
                    # if total_len > clen:
                        # break
                    if qu_cwnd.queue[qu_cwnd.qsize()-1] == -1:
                        break

                    # qu_ack = Queue.Queue()
                    t = threading.Thread(target=sniffer, args=(tcp_obj.src_port,dst_ip,timeout,qu_cwnd,tcp_obj,qu_ack,))
                    t.start()
                t.join()                    
                print("Got response from server")
                c1 = qu_cwnd.get()
                print("observed cwnd:",c1)
                cwnd_obs.append(c1)

                print("WAIT FOR SECONDS:",tt)
                time.sleep(tt)
                tt=tt+2

                if qu_ack.qsize() > 0:
                    for j in range(0,qu_ack.qsize()):
                        temp_ack_new = qu_ack.queue[qu_ack.qsize()-1-j]
                        if  temp_ack_new != -1:
                            ack_new = temp_ack_new
                            break
                    print("ACK NEW",ack_new)

                if tls_socket.ctx.must_encrypt:
                    pkt_to_be_sent = str(tls_to_raw(req_new, tls_socket.tls_ctx, True, tls_socket.compress_hook, tls_socket.pre_encrypt_hook, tls_socket.encrypt_hook))
                else:
                    pkt_to_be_sent = str(req_new)
                

                qu_cwnd = Queue.Queue()
                qu_ack = Queue.Queue()
                t = threading.Thread(target=sniffer, args=(tcp_obj.src_port,dst_ip,timeout,qu_cwnd,tcp_obj,qu_ack,))
                t.start()
                print("sniff thread started")

                tcp_obj.pkt[TCP].ack = ack_new
                send(tcp_obj.pkt/pkt_to_be_sent)
                tcp_obj.pkt[TCP].seq += len(pkt_to_be_sent)

                tls_socket.tls_ctx.insert(req_new, tls_socket._get_pkt_origin('out')) # called in sendall

                for_times = 100
                total_len = 0
                for i in range(0,for_times):
                    t.join()
                    print("sniff thread joined")

                    total_len = total_len + 1460.0 * qu_cwnd.queue[qu_cwnd.qsize()-1]
                    print("**************** TOTAL LEN:",total_len,clen)
                    # if total_len > clen:
                    #     break
                    if qu_cwnd.queue[qu_cwnd.qsize()-1] == -1:
                        break

                    # qu_ack = Queue.Queue()
                    t = threading.Thread(target=sniffer, args=(tcp_obj.src_port,dst_ip,timeout,qu_cwnd,tcp_obj,qu_ack,))
                    t.start()
                t.join()                    
                print("Got response from server")
                c1 = qu_cwnd.get()
                print("observed cwnd:",c1)
                cwnd_obs.append(c1)

                # print("WAIT FOR SECONDS:",tt)
                # time.sleep(tt)
                # tt=tt+2


            
            print('finished')
            arr = []
            arr.append(dst_name)
            for i in cwnd_obs:
                arr.append(i)
            print(arr)
            
            fw = open('ss-idle-record-443.csv','a')
            cw = csv.writer(fw)
            cw.writerow(arr)
            fw.close()

            delete_iptable_rule()
        except Exception,e:
            delete_iptable_rule()
            fw = open('ss-idle-record-443.csv','a')
            cw = csv.writer(fw)
            cw.writerow([dst_name,-1,-1,-1,-1])
            fw.close()
            print(dst_name,e)
            pass
    except Exception,e:
        print(dst_name,e)
        # delete_iptable_rule()
        pass


if __name__ == "__main__":

    f = open('top-1m.csv')
    c = csv.reader(f)
    

    for row in c:
        print(row)
        try:
            if int(row[0]) > 0:
                if int(row[0]) == 10000:
                    break
                dst_name = 'www.'+str(row[1]).strip()
                # dst_name = 'magnus.cs.duke.edu'
                clen = 0
                # response = urllib2.urlopen('https://'+dst_name+'/')
                # html = response.read()
                # print(html)
                # print(response.info())
                # clen = response.info().get('Content-Length')
                # if clen:
                    # print("not none")
                # else:
                    # print("none")
                    # clen = len(html)
                # print(len(html))
                # print(clen)
                t = threading.Thread(target=operation, args=(dst_name,clen,))
                t.start()
                t.join(60)
                        
                # dst_name = 'www.google.com'
                # https://www.google.com/about/main/gender-equality-films/
                # dst_name = "magnus.cs.duke.edu"
                # dst_name = 'www.yahoo.com'
                # dst_name = 'www.youtube.com'
                # dst_name = 'www.facebook.com'
                # dst_name = 'www.gmail.com'
                # dst_name = 'www.msn.com'
                # dst_name = 'www.espn.com'
                # dst_name = 'users.cs.duke.edu'
                # dst_name = 'www.wikipedia.org'
                
            
        except Exception,e:
            print(row,e)
            pass
                        