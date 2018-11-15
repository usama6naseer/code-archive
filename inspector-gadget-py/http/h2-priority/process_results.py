import csv
import sys
import pickle
import os
import operator
from os.path import dirname, abspath
import math

def save_obj(obj, name , parent_dir):
    with open(parent_dir + 'obj/'+ name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name , parent_dir):
    with open(parent_dir + 'obj/' + name + '.pkl', 'rb') as f:
        return pickle.load(f)

def get_median(arr):
	arr_s = sorted(arr)
	return arr_s[math.floor(len(arr)/2)]

if __name__ == "__main__":
	parent_dir = '/Users/usama/Projects/mobi-qoe/'
	obj_files = os.listdir(parent_dir + 'obj')

	plt_map = {}

	cr = csv.reader(open('testbed_results/result_v1.csv', 'r'))
	for row in cr:
		# print(row)
		plt = float(row[0])
		site = row[1].split('/')[0]
		defp_pri = int(row[2])
		css_pri = int(row[3])
		img_pri = int(row[4])
		js_pri = int(row[5])
		index_pri = int(row[6])
		pri_flag = int(row[7])
		fname = int(row[8])
		turn = int(row[9])
		bw = float(row[10])
		delay = float(row[11])
		loss = float(row[12])

		# print(plt, site, defp_pri, css_pri, img_pri, js_pri, index_pri, pri_flag, fname, turn, bw, delay, loss)
		# sys.exit()

		key = repr([bw, delay, loss])
		pri_key = repr([defp_pri, css_pri, img_pri, js_pri, index_pri, pri_flag])

		if key not in plt_map:
			plt_map[key] = {}

		if site not in plt_map[key]:
			plt_map[key][site] = {}

		if pri_key not in plt_map[key][site]:
			plt_map[key][site][pri_key] = []

		temp_map = plt_map[key][site][pri_key]
		temp_map.append(plt)

	avg_plt_map = {}

	better_than_def = []
	better_than_worst = []
	better_than_ng_def = []
	better_than_frx = []

	cw = csv.writer(open('plt-comp.csv', 'w'))
	cw1 = csv.writer(open('temp-plt-comp.csv', 'w'))
	for key in plt_map:
		avg_plt_map[key] = {}

		for site in plt_map[key]:
			avg_plt_map[key][site] = {}

			def_plt = ['', 0]
			best_plt = ['', 0]
			worst_plt = ['', 0]
			ng_def_plt = ['', 0]
			frx_plt = ['', 0]

			for pri_key in plt_map[key][site]:
				avg_plt_arr = []

				for plt in plt_map[key][site][pri_key]:
					avg_plt_arr.append(plt)

				# plt = sum(avg_plt_arr) / len(avg_plt_arr)
				plt = get_median(avg_plt_arr)
				if len(avg_plt_arr) < 3:
					print(avg_plt_arr, plt)

				avg_plt_map[key][site][pri_key] = sorted(avg_plt_arr)

				if pri_key == '[-1, -1, -1, -1, 16, 0]':
					def_plt[0] = pri_key
					def_plt[1] = plt

				if best_plt[1] == 0 or plt < best_plt[1]:
					best_plt[0] = pri_key
					best_plt[1] = plt

				if worst_plt[1] == 0 or plt > worst_plt[1]:
					worst_plt[0] = pri_key
					worst_plt[1] = plt

				if pri_key == '[32, 32, 32, 12, 16, 1]':
					ng_def_plt[0] = pri_key
					ng_def_plt[1] = plt

				if pri_key == '[8, 24, 16, 8, 32, 1]':
					frx_plt[0] = pri_key
					frx_plt[1] = plt

			# print(def_plt, best_plt, worst_plt)

			netcond = eval(key)
			
			per_def = (def_plt[1] - best_plt[1]) * 100 / def_plt[1]
			better_than_def.append(per_def)

			per_wor = (worst_plt[1] - best_plt[1]) * 100 / worst_plt[1]
			better_than_worst.append(per_wor)

			per_ng_def = (ng_def_plt[1] - best_plt[1]) * 100 / ng_def_plt[1]
			better_than_ng_def.append(per_ng_def)

			per_frx = (frx_plt[1] - best_plt[1]) * 100 / frx_plt[1]
			better_than_frx.append(per_frx)

			cw.writerow([netcond[0], netcond[1], netcond[2], site, per_def, per_wor, def_plt[1], avg_plt_map[key][site][def_plt[0]], best_plt[0], best_plt[1], avg_plt_map[key][site][best_plt[0]], worst_plt[0], worst_plt[1], avg_plt_map[key][site][worst_plt[0]]])
			cw1.writerow([netcond[0], netcond[1], netcond[2], site, per_ng_def, per_frx, per_def, per_wor])

	better_than_def = sorted(better_than_def)
	better_than_worst = sorted(better_than_worst)
	better_than_ng_def = sorted(better_than_ng_def)
	better_than_frx = sorted(better_than_frx)

	cw = csv.writer(open('plt-comp-cdf.csv', 'w'))
	print(len(better_than_def), len(better_than_worst), len(better_than_ng_def), len(better_than_frx))

	for i in range(0, len(better_than_def)):
		cw.writerow([i, better_than_def[i], better_than_worst[i], (i + 1) / len(better_than_def), better_than_ng_def[i], better_than_frx[i]])




















