import csv
import time
import os
import subprocess
from subprocess import Popen, PIPE
from timeout import timeout
import errno
import sys


@timeout(7, os.strerror(errno.ETIMEDOUT))
def h2_priorities(dst, port, har_name, ua_s, dep):
	print('Testing with dep =', dep)
	# if dep == 0:
	# 	cm = ['nghttp', '-a', 'https://www.' + dst, '-r', 'har/' + str(dep) + '_' + str(ua_s) + '_' + str(har_name) + '.har', '-nv', '--no-dep', "--header=User-Agent:" + str(ua)]
	# else:
	# 	cm = ['nghttp', '-a', 'https://www.' + dst, '-r', 'har/' + str(dep) + '_' + str(ua_s) + '_' + str(har_name) + '.har', '-nv', "--header=User-Agent:" + str(ua)]

	# url = 'https://nghttp2.org/documentation/'
	# url = 'https://primus.cs.duke.edu/'
	url = 'https://www.youtube.com/'

	if dep == 0:
		cm = ['nghttp', '-nva', url, '--no-dep']
	else:
		cm = ['nghttp', '-nva', url, '--max-concurrent-streams=1']

	process = Popen(cm, stdout=PIPE, stderr=PIPE, shell=False)
	stdout, stderr = process.communicate()
	out = stdout.decode("utf-8").strip()
	# err = stderr.decode("utf-8").strip()
	# print(out)
	# print(err)
	return out

def parse_output(out, dep):
	vec = out.split('\n')
	send_flag = 0
	send_map = {}
	rcv_map = {}
	curr_send_stream_id = -1

	for line in vec:
		# print(line)
		if send_flag == 1 and line[0] == '[':
			send_flag = 0
			# sys.exit()

		if 'send' in line or send_flag == 1:

			if 'send' in line and 'HEADERS' in line:
				send_flag = 1
				tokens = line.split(' ')
				time_str = line.split(']')[0]
				time_str = time_str.replace('[', '')
				time_str = time_str.replace(']', '')
				time_str = time_str.replace(' ', '')
				timestamp = float(time_str)

				length = -1
				stream_id = -1
				flags = -1

				for token in tokens:
					if 'length' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						length = int(temp_str)

					elif 'stream_id' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						stream_id = int(temp_str)

					elif 'flags' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						flags = temp_str

				curr_send_stream_id = stream_id

				if curr_send_stream_id not in send_map:
					send_map[curr_send_stream_id] = [[length, stream_id, flags, timestamp]]
				else:
					temp = send_map[curr_send_stream_id]
					temp.append([length, stream_id, flags, timestamp])


			elif send_flag == 1:
				tokens = line.split(' ')
				dep_stream_id = -1
				weight = -1
				exclusive = -1

				temp_flag = 0
				for token in tokens:
					if 'dep_stream_id' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						dep_stream_id = int(temp_str)
						temp_flag = 1

					elif 'weight' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						weight = int(temp_str)
						temp_flag = 1

					elif 'exclusive' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						exclusive = int(temp_str)
						temp_flag = 1

				if temp_flag == 1:
					temp_full = send_map[curr_send_stream_id]
					temp = temp_full[len(temp_full) - 1]
					temp.append(dep_stream_id)
					temp.append(weight)
					temp.append(exclusive)

				if 'path' in line:
					path = line.split(':path:')[1]
					path = path.strip()
					temp_full = send_map[curr_send_stream_id]
					temp = temp_full[len(temp_full) - 1]
					temp.append(path)
					

		elif 'recv' in line:
			if 'DATA' in line or 'SETTINGS' in line:
				tokens = line.split(' ')
				time_str = line.split(']')[0]
				time_str = time_str.replace('[', '')
				time_str = time_str.replace(']', '')
				time_str = time_str.replace(' ', '')
				timestamp = float(time_str)

				length = -1
				stream_id = -1
				flags = -1

				for token in tokens:
					if 'length' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						length = int(temp_str)

					elif 'stream_id' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						stream_id = int(temp_str)

					elif 'flags' in token:
						temp = token.split('=')
						temp_str = temp[1].strip()
						temp_str = temp_str.replace(',','')
						temp_str = temp_str.replace('>','')
						temp_str = temp_str.replace(')','')
						flags = temp_str

				# print(length, stream_id, flags)
				if stream_id not in send_map:
					print('stream_id:', stream_id, '| length:', length, '| flags:', flags)
				else:
					print('stream_id:', stream_id, '| length:', length, '| flags:', flags, send_map[stream_id])





if __name__ == "__main__":
	dst_url_orig = 'google.com'
	dst_url = 'www.' + dst_url_orig
	dst_port = 443
	har_name = ''
	ua = ''

	for dep in [0, 1]:
		out = h2_priorities(dst_url_orig, dst_port, har_name, ua, dep)
		parse_output(out, dep)













