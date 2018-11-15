import csv
import sys
import pickle
import os
import operator
from os.path import dirname, abspath

def save_obj(obj, name , parent_dir):
    with open(parent_dir + 'obj/'+ name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name , parent_dir):
    with open(parent_dir + 'obj/' + name + '.pkl', 'rb') as f:
        return pickle.load(f)


if __name__ == "__main__":
	parent_dir = '/Users/usama/Projects/mobi-qoe/'
	obj_files = os.listdir(parent_dir + 'obj')

	hostname_to_cdn_map = load_obj('HOSTNAME_TO_CDN_MAP', parent_dir)
	hostname_to_cdn_map = hostname_to_cdn_map['us']
	server_map = load_obj('HOST_TO_SERVER', parent_dir)
	server_map = server_map['us']

	cr = csv.reader(open('pri_results_0.csv', 'r'))
	for row in cr:
		# print(row)
		site = row[1]
		server = ''
		cdn = ''

		if site in server_map:
			server = server_map[site][0]
		if site in hostname_to_cdn_map:
			cdn = hostname_to_cdn_map[site]

		if server != '' or cdn != '':
			print(site, server, cdn)





			# sys.exit()