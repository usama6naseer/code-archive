import subprocess
from subprocess import Popen, PIPE
import csv
import os
import sys
from timeout import timeout
import errno
import socket
import ssl

# https://wiki.openssl.org/index.php/Manual:S_client(1)

@timeout(5, os.strerror(errno.ETIMEDOUT))
def test_tls_version(dst, port, tls_v):
	cm = ['/usr/local/curl/bin/curl','-sS', tls_v, 'https://www.'+dst]
	process = Popen(cm, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	output = stderr.decode("utf-8").strip()
	vec = output.split(' ')
	if len(vec) > 1:
		if "error" in output or "null" in output:
			return False
	return True

def ocsp(dst, port):
	# openssl s_client -connect www.espn.com:443 -status
	tout = 2
	cm = ['timeout', str(tout), 'openssl', 's_client', '-connect', 'www.'+dst+':'+str(port), '-status']
	# print(cm)
	process = Popen(cm, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	if 'failure' not in stderr.decode("utf-8").strip():
		output = stdout.decode("utf-8").strip()
		vec = output.split('\n')
		ocsp_flag = 0
		ocsp_row = 0
		ocsp_return = -1
		renog_return = -1
		read_bytes = -1
		write_bytes = -1
		if len(vec) > 1:
			for row in range(0, len(vec)):
				# print(vec[row])
				if row == ocsp_row + 1:
					if ocsp_flag == -1:
						# return 0
						ocsp_return = 0
						break
					elif ocsp_flag == 1 and '==' in vec[row]:
						# return 1
						ocsp_return = 1
						break

				if 'OCSP' in vec[row]:
					# print(vec[row])
					status = vec[row].split(':')
					ocsp_row = row

					if len(status) > 1 and 'no' in status[1]:
						ocsp_flag = -1
					else:
						ocsp_flag = 1

			for row in range(0, len(vec)):
				if 'Renegotiation' in vec[row]:
					if 'NOT' in vec[row]:
						renog_return = 0
					else:
						renog_return = 1

			for row in range(0, len(vec)):
				if 'handshake' in vec[row] and 'read' in vec[row] and 'written' in vec[row] and 'bytes' in vec[row]:
					v = vec[row].split(' ')
					for index in range(0,len(v)):
						if v[index] == 'read':
							read_bytes = int(v[index+1])
						elif v[index] == 'written':
							write_bytes = int(v[index+1])

		return [ocsp_return, renog_return, read_bytes, write_bytes]
		# return True
	else:
		return [-1, -1, -1, -1]

@timeout(5, os.strerror(errno.ETIMEDOUT))
def alpn(HOST, PORT):
	ctx = ssl.create_default_context()
	ctx.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
	conn = ctx.wrap_socket(
	   socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
	conn.connect((HOST, PORT))

	# print(ctx.session_stats())
	# print(conn.session.has_ticket())
	# print('compression',conn.compression())
	# print('Next protocol:', conn.selected_alpn_protocol())

	return conn.selected_alpn_protocol()


def forward_secrecy(dst, port):
	# openssl s_client -connect gmail.com:443 -cipher ECDHE
	tout = 2
	cm = ['timeout', str(tout), 'openssl', 's_client', '-connect', 'www.'+dst+':'+str(port), '-cipher', 'ECDHE']
	process = Popen(cm, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	if 'failure' not in stderr.decode("utf-8").strip():
		output = stdout.decode("utf-8").strip()
		if len(output.split('\n')) > 2:
			return 1
		else:
			return 0
	else:
		return 0

def session_id_ticket(dst, port, tout):
	# openssl s_client -connect akamai.com:443 -reconnect
	# cm = ['timeout', str(tout), 'openssl', 's_client', '-connect', 'www.'+dst+':'+str(port), '-reconnect', '-cipher', 'ECDHE-RSA-RC4-SHA']
	cm = ['timeout', str(tout), 'openssl', 's_client', '-connect', 'www.'+dst+':'+str(port), '-reconnect']
	process = Popen(cm, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	cnt = 0
	session_return = -1
	ticket_return = 0
	ticket_time_return = 0
	if 'failure' not in stderr.decode("utf-8").strip():
		# print(stdout.decode("utf-8").strip())
		# print('*************')
		# print(stderr.decode("utf-8").strip())
		output = stdout.decode("utf-8").strip()
		vec = output.split('\n')
		reused_flag = 0
		if len(vec) > 1:
			# print(len(vec))
			for row in range(0, len(vec)):
				if 'CONNECTED' in vec[row]:
					if len(vec) >= row+1:
						cnt += 1
						if 'Reused' in vec[row+2]:
							reused_flag = 1
							break

			if cnt <= 1:
				session_return = -2
			else:
				session_return = reused_flag

			cnt = 0
			for row in range(0, len(vec)):
				if 'TLS' in vec[row] and 'session' in vec[row] and 'ticket' in vec[row]:
					if 'lifetime' in vec[row]:
						v = vec[row].split(':')[1]
						v = v.strip()
						v = v.split(' ')[0]
						ticket_time_return = int(v)
					else:
						if 'Start' not in vec[row]:
							ticket_return = 1

			return [session_return, ticket_return, ticket_time_return]
		else:
			return [session_return, ticket_return, ticket_time_return]
	else:
		return [session_return, ticket_return, ticket_time_return]
	


if __name__ == "__main__":
	f = open('top-1m.csv','r')
	c = csv.reader(f)
	for row in c:
		if int(row[0]) > 10000:
			break
		dst = row[1]
		# dst = "live.com"

		for tls_v in ['--sslv3','--tlsv1','--tlsv1.1','--tlsv1.2']:
                       try:
                               out = test_tls_version(dst, 443, tls_v)
                               print(dst, tls_v, out)

                               try:
                                       f2 = open('final_tls.csv','a')
                                       c2 = csv.writer(f2)
                                       c2.writerow([dst, tls_v, out])
                                       f2.close()
                               except Exception as e:
                                       print(2,dst,e)
                                       pass

                       except Exception as e:
                               print(dst,e)
                               pass
		'''
		session_return = -1
		ticket_return = -1
		ticket_time_return = -1
		try:
			out = session_id_ticket(dst, 443, 3)
			if out[0] == -2:
				out = session_id_ticket(dst, 443, 8)
			print('session_id_ticket:', dst, out)
			session_return = out[0]
			ticket_return = out[1]
			ticket_time_return = out[2]
		except Exception as e:
			print('session_id_ticket:',dst,e)
			pass

		fs = -1
		try:
			fs = forward_secrecy(dst, 443)
			print('forward_secrecy:', dst, fs)
		except Exception as e:
			print('forward_secrecy:',dst,e)
			pass

		alpn_ret = -1
		http_v = ''
		try:
			out = alpn(dst, 443)
			http_v = out
			print('alpn:',dst, out)
			if out is None:
				alpn_ret = 0
			else:
				alpn_ret = 1
		except Exception as e:
			print('alpn:',dst,e)
			pass

		ocsp_return = -1
		renog_return = -1
		read_bytes = -1
		write_bytes = -1
		try:
			out = ocsp(dst, 443)
			print('ocsp:',dst, out)
			ocsp_return = out[0]
			renog_return = out[1]
			read_bytes = out[2]
			write_bytes = out[3]
		except Exception as e:
			print('ocsp:',dst,e)
			pass

		# break
		cw = csv.writer(open('tls_res.csv','a'))
		cw.writerow([row[0], row[1], session_return, ticket_return, ticket_time_return, fs, alpn_ret, http_v, ocsp_return, renog_return, read_bytes, write_bytes])
		'''

