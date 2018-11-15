import csv
import time
import os
import subprocess
from subprocess import Popen, PIPE
from timeout import timeout
import errno

@timeout(7, os.strerror(errno.ETIMEDOUT))
def h2_priorities(dst, port, har_name, ua, tout, ua_s):
	for dep in [0,1]:
		if dep == 0:
			cm = ['nghttp', '-a', 'https://www.' + dst, '-r', 'har/' + str(dep) + '_' + str(ua_s) + '_' + str(har_name) + '.har', '-nv', '--no-dep', "--header=User-Agent:" + str(ua)]
		else:
			cm = ['nghttp', '-a', 'https://www.' + dst, '-r', 'har/' + str(dep) + '_' + str(ua_s) + '_' + str(har_name) + '.har', '-nv', "--header=User-Agent:" + str(ua)]

		process = Popen(cm, stdout=PIPE, stderr=PIPE, shell=False)
		stdout, stderr = process.communicate()
		out = stdout.decode("utf-8").strip()
		err = stderr.decode("utf-8").strip()
		# print(out)
		# print('************************************')
		# print(err)

@timeout(5, os.strerror(errno.ETIMEDOUT))
def h2_num_stream_win_size(dst, port, ua, tout):
	cm = ['nghttp', '-a', 'https://www.' + dst, '-nv', "--header=User-Agent:" + str(ua)]
	process = Popen(cm, stdout=PIPE, stderr=PIPE, shell=False)
	stdout, stderr = process.communicate()
	out = stdout.decode("utf-8").strip()
	err = stderr.decode("utf-8").strip()
	# print(out)
	# print('************************************')
	# print(err)
	rcv_found = 0
	SETTINGS_MAX_CONCURRENT_STREAMS = -1
	SETTINGS_INITIAL_WINDOW_SIZE = -1
	SETTINGS_MAX_HEADER_LIST_SIZE = -1
	SETTINGS_HEADER_TABLE_SIZE = -1
	SETTINGS_MAX_FRAME_SIZE = -1
	vec = out.split('\n')
	# print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
	for row in vec:
		# print(row)
		if 'recv' in row:
			rcv_found = rcv_found + 1
		if rcv_found == 1:
			# print(row)
			if 'SETTINGS_MAX_CONCURRENT_STREAMS' in row:
				v = row.replace(']','')
				v = v.split(':')
				SETTINGS_MAX_CONCURRENT_STREAMS = int(v[1])

			if 'SETTINGS_INITIAL_WINDOW_SIZE' in row:
				v = row.replace(']','')
				v = v.split(':')
				SETTINGS_INITIAL_WINDOW_SIZE = int(v[1])

			if 'SETTINGS_MAX_HEADER_LIST_SIZE' in row:
				v = row.replace(']','')
				v = v.split(':')
				SETTINGS_MAX_HEADER_LIST_SIZE = int(v[1])

			if 'SETTINGS_HEADER_TABLE_SIZE' in row:
				v = row.replace(']','')
				v = v.split(':')
				SETTINGS_HEADER_TABLE_SIZE = int(v[1])

			if 'SETTINGS_MAX_FRAME_SIZE' in row:
				v = row.replace(']','')
				v = v.split(':')
				SETTINGS_MAX_FRAME_SIZE = int(v[1])

		if rcv_found > 1:
			break
	return [SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE, SETTINGS_HEADER_TABLE_SIZE, SETTINGS_MAX_FRAME_SIZE]

@timeout(5, os.strerror(errno.ETIMEDOUT))
def http_version_test(dst, port, ua, tout):
	cm = ['nghttp', '-a', 'https://www.' + dst, '-nv', "--header=User-Agent:" + str(ua)]
	process = Popen(cm, stdout=PIPE, stderr=PIPE, shell=False)
	stdout, stderr = process.communicate()
	out = stdout.decode("utf-8").strip()
	err = stderr.decode("utf-8").strip()
	# print(out)
	# print('************************************')
	# print(err)

	if 'ERROR' in err or 'not selected' in err or 'expects h2' in err:
		return 1
	else:
		return 2

if __name__ == "__main__":
	tout = 5
	f = open('top-1m.csv','r')
	c = csv.reader(f)
	for row in c:
		print('testing:', row[1], row[0])
		ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36'
		ua_map = {1: 'Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36',
					2: 'Mozilla/5.0 (Linux; Android 4.4.3; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/47.1.79 like Chrome/47.0.2526.80 Safari/537.36',
					3: 'Mozilla/5.0 (CrKey armv7l 1.5.16041) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.0 Safari/537.36',
					4: 'Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)',
					5: 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36',
					6: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1'}

		for ua_s in ua_map:
			ua = ua_map[ua_s]
			try:
				http_version = http_version_test(row[1], 443, ua, tout)

				cw = csv.writer(open('http_version.csv','a'))
				cw.writerow([row[0], row[1], http_version, ua_s])

				if http_version == 2:		
					# h2_priorities(row[1], 443, int(row[0]), ua, tout+2, ua_s)
					
					out = h2_num_stream_win_size(row[1], 443, ua, tout)
					print(out)
					cw1 = csv.writer(open('http2_full.csv','a'))
					cw1.writerow([row[0], row[1], out[0], out[1], out[2], out[3], out[4], ua_s])
			except Exception as e:
				print(row, e)
				pass

		if (int(row[0]) == 10000):
			break


	
