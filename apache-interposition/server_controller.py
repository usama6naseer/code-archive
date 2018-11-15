import csv
import os
import operator
from datetime import datetime
import time
import math

# sudo tc qdisc change dev eth0 root netem loss 0%

class _perf_obj():
    def __init__(self, t1, t2):
        self.time = t1
        self.bytes = t2

def print_map(ip_perf_map):
	for i in ip_perf_map:
		print('-->',i)
		for j in ip_perf_map[i]:
			print('---->',j)
			for k in ip_perf_map[i][j]:
				print('------>',k.time, k.bytes)

def get_pruned_time(req_time):
	try:
		vec = req_time.split('[')
		vec = vec[1].split(' ')
		datetime_object = datetime.strptime(vec[0], '%d/%b/%Y:%H:%M:%S')
		return datetime_object.timestamp()
	except Exception as e:
		print('get_pruned_time()',e)
		pass
		return 0

def get_log_file(log_dir):
	all_files = []
	for file in os.listdir(log_dir):
	    if 'plt' in file:
	        vec = file.split('.')
	        all_files.append(int(vec[1]))

	sorted_all_files = sorted(all_files)
	return sorted_all_files

def strip_field(s):
	v = s.split('#')
	return v[1].strip()

if __name__ == "__main__":
	curr_dir = os.getcwd()
	tmp_dir = '/tmp/'
	tcp_grace_timeout = 5

	# map_cwnd = {}
	# map_cwnd_max = {}
	while(True):
		try:
			c_file = open('/tmp/stats/tcp.csv','a')
			c_results = csv.writer(c_file)
						
			all_files = []
			for file in os.listdir(tmp_dir):
			    if '_stt' in file and file[0] != '.':
			        all_files.append(file)

			print('\ntcp_all_files:', all_files)
			# done_reading = []

			if (len(all_files) > 0):
				for i in all_files:
					f_name = tmp_dir + i
					print('\nreading', f_name, '...')
					
					start_reading_flag = 0
					cn = 0
					rtt_avg = 0
					total_retrans_max = 0
					cwnd_trace = []
					time_trace = []
					ssthresh_trace = []
					total_packets = 0
					total_packets_timer = 0
					
					try:
						f = open(f_name, 'r')
						for line in f:
							vec = line.split('|')
							ip = strip_field(vec[0])
							port = strip_field(vec[1])
							time_ms = float(strip_field(vec[2]))
							# time_sec = float(time_ms) / 1000.0
							# time_now = strip_field(vec[3])
							cwnd = int(strip_field(vec[4]))
							# state = strip_field(vec[5])
							rtt = float(strip_field(vec[6])) / 1000.0
							# sacked = int(strip_field(vec[7]))
							unacked = int(strip_field(vec[8]))
							ssthresh = int(strip_field(vec[9]))
							mss = int(strip_field(vec[10]))
							retransmits = int(strip_field(vec[11]))
							lost = int(strip_field(vec[12]))
							# last_data_sent = int(strip_field(vec[13]))
							# last_ack_recv = int(strip_field(vec[14]))
							total_retrans = int(strip_field(vec[15]))

							# print(cwnd, time_ms, rtt, lost, retransmits, total_retrans)
							# rtt calculation
							if rtt_avg == 0:
								rtt_avg = rtt
							else:
								rtt_avg = (rtt_avg + rtt)/2.0

							# ssthresh calculation
							if ssthresh not in ssthresh_trace:
								ssthresh_trace.append(ssthresh)

							# total retransmits calculation
							if total_retrans > total_retrans_max:
								total_retrans_max = total_retrans

							# total_packets calculation
							if total_packets == 0:
								total_packets = unacked
								total_packets_timer = time_ms
							else:
								if time_ms >= total_packets_timer + rtt_avg:
									total_packets = total_packets + unacked
									total_packets_timer = time_ms

							# cwnd calculation
							if cn == 0:
								curr_time = datetime.now()
								curr_time_sec = curr_time.timestamp()*1000.0
								# print(time_now, time_sec, curr_time_sec)
								if (curr_time_sec - time_ms > 5*1000):
									# file is old enough to be read
									# done_reading.append(f_name)
									start_reading_flag = 1
							cn += 1
							if start_reading_flag == 1:
								cwnd_trace.append(cwnd)
								time_trace.append(time_ms)
						
						# file read done
						max_cwnd_trace = []
						max_cwnd = max(cwnd_trace)
						max_time = 0
						low_found = 0
						low_time = 0
						for i in range(0, len(cwnd_trace)):
							if low_found == 1:
								if time_trace[i] > low_time + (rtt_avg * 0.75) and time_trace[i] < low_time + (rtt_avg * 1.25):
									max_cwnd_trace.append(cwnd_trace[i])
									low_time = time_trace[i]
							else:
								if cwnd_trace[i] == max_cwnd and max_time == 0:
									max_time = time_trace[i]
								if cwnd_trace[i] < max_cwnd:
									if time_trace[i] < max_time + (rtt_avg * 1.5):
										max_cwnd_trace.append(cwnd_trace[i])
										low_found = 1
										low_time = time_trace[i]
							if len(max_cwnd_trace) >= 10:
								break
						print(max_cwnd, max_cwnd_trace)
						if len(max_cwnd_trace) != 0:
							if max_cwnd_trace[0] >= max_cwnd/2:
								max_cwnd = float(sum(max_cwnd_trace)) / float(len(max_cwnd_trace))
						print(round(max_cwnd), rtt_avg, max(ssthresh_trace), min(ssthresh_trace), total_packets, total_retrans_max, total_retrans_max*100/total_packets)
						c_results.writerow([ip, port, round(max_cwnd), rtt_avg, max(ssthresh_trace), min(ssthresh_trace), total_packets, total_retrans_max, total_retrans_max*100/total_packets])
						os.remove(f_name)

					except Exception as e:
						print("read file",e)
						pass
			c_file.close()
			# break

		except Exception as e:
			print(2, 'tcp read', e)
			pass

		all_files = []
		seen = 0
		prev_file = ''
		prev_file_time = 0
		ip_perf_map = {}
		curr_dir = os.getcwd()
		log_dir = '/usr/loocal/a1/logs/'
		for file in os.listdir(log_dir):
		    if 'plt' in file:
		        vec = file.split('.')
		        all_files.append(int(vec[1]))

		sorted_all_files = sorted(all_files)
	
		# while(True):
		try:
			c_file = open('/tmp/stats/plt.csv','a')
			c_results = csv.writer(c_file)

			sorted_all_files = get_log_file(log_dir)
			print('\nsorted_all_files:',sorted_all_files)
			to_be_removed = []

			if (len(sorted_all_files) > 0):
				for i in sorted_all_files:
					f_name = log_dir + 'plt.' + str(i)
					print('seen:',seen, i)
					if i >= seen:
						print('Reading', 'plt.' + str(i), '...')
						seen = i
						f = open(f_name, 'r')
						for line in f:
							# print(line)
							vec = line.split('|')
							client_ip = vec[0]
							remote_host_ip = vec[1]
							local_ip = vec[2]
							req_time = vec[3].strip()
							req_line = vec[4].strip()
							status_code = vec[5]
							res_bytes = vec[6]
							plt_time_sec = vec[7]
							plt_time_micsec = vec[8]
							ua_string = vec[9]
							# print('client_ip',client_ip,'remote_host_ip',remote_host_ip,'local_ip',local_ip,'req_time',req_time,'req_line',req_line,'status_code',status_code,'res_bytes',res_bytes, \
								# 'plt_time_sec',plt_time_sec,'plt_time_micsec',plt_time_micsec,'ua_string',ua_string)
							req_obj = ""
							try:
								temp = req_line.split(' ')
								req_obj = temp[1]
							except Exception as e:
								print('req_obj',e)
								req_obj = req_line
							req_time_pruned = get_pruned_time(req_time)
							print('req_obj', req_obj, req_time_pruned)
							if req_time_pruned > prev_file_time:
								prev_file_time = req_time_pruned

								print('appending ...')
								if client_ip in ip_perf_map:
									temp = ip_perf_map[client_ip]
									if req_obj in temp:
										temp_vec = temp[req_obj]
										temp_vec.append(_perf_obj(plt_time_micsec, res_bytes))
										temp[req_obj] = temp_vec
										ip_perf_map[client_ip] = temp
										c_results.writerow([req_time, req_obj, client_ip, plt_time_micsec, res_bytes])
									else:
										temp[req_obj] = [_perf_obj(plt_time_micsec, res_bytes)]
										ip_perf_map[client_ip] = temp
										c_results.writerow([req_time, req_obj, client_ip, plt_time_micsec, res_bytes])
								else:
									temp = {}
									temp[req_obj] = [_perf_obj(plt_time_micsec, res_bytes)]
									ip_perf_map[client_ip] = temp
									c_results.writerow([req_time, req_obj, client_ip, plt_time_micsec, res_bytes])
						print_map(ip_perf_map)

					else:
						if len(sorted_all_files) > 1:
							print('Deleting', 'plt.' + str(i), '...')
							# sorted_all_files.remove(i)
							to_be_removed.append(i)
							# os.remove(f_name)

					# aggregate_results(ip_perf_map)
			c_file.close()
			# else:
			# 	break
			for m in to_be_removed:
				sorted_all_files.remove(m)
				os.remove(log_dir + 'plt.' + str(m))
			
			# write_to_file(ip_perf_map)
		except Exception as e:
			print(1, 'log read:', e)
			pass
		time.sleep(5)
