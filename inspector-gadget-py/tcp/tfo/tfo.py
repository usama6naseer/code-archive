from scapy.all import sr1, IP, TCP
import csv
from timeout import timeout
import os
import errno
import multiprocessing
import time

@timeout(5, os.strerror(errno.ETIMEDOUT))
def test_tfo(dst,dport):
	res = sr1(IP(dst=dst)/TCP(dport=dport,flags="S",options=[('TFO', '')]), verbose=False)
	if res is not None:
		return 'TFO' in dict(res[1].options)
	else:
		False

def worker(sites, i):
	for dst in sites:
		try:
			print i
			out = test_tfo(dst, 443)
			# print dst, out
			try:
				f2 = open(str(i)+'final_tfo.csv','a')
				c2 = csv.writer(f2)
				c2.writerow([dst, out])
				f2.close()
			except Exception,e:
				print(2,dst,e)
				pass
		except Exception,e:
			print dst,e
			pass


if __name__ == "__main__":
	f = open("top-1m.csv",'r')
	c = csv.reader(f)
	cnt = 0
	sites = []
	ps = []

	for row in c:
		sites.append(row[1])
		if len(sites) >= 5:
			# print len(sites)
			cnt += 1
			try:
				p = multiprocessing.Process(target=worker, args=(sites, cnt,))
				p.start()
				ps.append(p)
			except Exception,e:
				print("2: ", e)
				pass
			sites = []

		if cnt == 5:
			timeout = 10
			start = time.time()
			for p in ps:
				while True:
					present = time.time()
					time.sleep(0.5)

					if p.is_alive() == False:
						break

					if present - start > timeout:				
						p.terminate()
						break
				try:
					p.terminate()
				except:
					pass

				try:
					p.join()
				except:
					pass

			cnt = 0
			ps = []
		
		if int(row[0]) > 10000:
			break
