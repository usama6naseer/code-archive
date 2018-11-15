import subprocess
from subprocess import Popen, PIPE
import csv
import os
import sys
from timeout import timeout
import errno

@timeout(5, os.strerror(errno.ETIMEDOUT))
def test_tls_version(dst, port, tls_v):
	cm = ['curl-7.56.1/local/bin/curl','-sS', tls_v, 'https://www.' + dst]
	process = Popen(cm, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	output = stderr.decode("utf-8").strip()
	vec = output.split(' ')
	# curl: (27) SSL: couldn't create a context: error:140A90C4:SSL routines:SSL_CTX_new:null ssl method passed
	# print len(vec)
	if len(vec) > 1:
		if "error" in output or "null" in output:
			return False
	return True

# https://support.citrix.com/article/CTX229287
def test_tls_1_3(dst, port):
	cm = ['curl-7.56.1/local/bin/curl','-sS', tls_v, 'https://www.' + dst]
	process = Popen(cm, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	output = stderr.decode("utf-8").strip()
	vec = output.split(' ')


if __name__ == "__main__":
	f = open('top-1m.csv','r')
	c = csv.reader(f)
	for row in c:
		dst = row[1]
		dst = "facebook.com"

		try:
			out = test_tls_1_3(dst, 443)
			print(dst, out)

		except Exception as e:
			print(dst,e)
			pass		

		# for tls_v in ['--sslv3','--tlsv1','--tlsv1.1','--tlsv1.2']:
		# 	try:
		# 		out = test_tls_version(dst, 443, tls_v)
		# 		print dst, tls_v, out

		# 		try:
		# 			f2 = open('final_tls.csv','a')
		# 			c2 = csv.writer(f2)
		# 			c2.writerow([dst, tls_v, out])
		# 			f2.close()
		# 		except Exception,e:
		# 			print(2,dst,e)
		# 			pass

		# 	except Exception,e:
		# 		print(dst,e)
		# 		pass
		break
