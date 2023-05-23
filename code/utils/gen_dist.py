import os
import sys
import numpy as np
import glob
from collections import Counter
import random
import pickle
import argparse


def normalize_dist(dist):
	base = sum(dist.values())
	_dist = {}
	for k in dist:
		_dist[k] = float(dist[k] / base)
	return _dist

def gen_dist_db(trace_dir, output_file):
	"""
	Generate traffic size, timing, direction distributions based on 
	the reference traces

	The excpted trace format is {time,direction * size} 
	or {time,direction * size,flow id}
	"""

	DIR_DIST = []
	IN_SIZE_DIST = []
	OUT_SIZE_DIST = []
	SAME_GAP_DIST = []
	DIFF_GAP_DIST = []
	ALL_GAP_DIST = []

	
	fs = glob.glob("%s/*" % trace_dir) # if the directory structure is {trace_dir}/*
	fs.sort()

	for _f in fs:
		print (_f)
		assert "," in open(_f).readline(), "The trace delimiter is excpted to be comma"
		tms = []
		for l in open(_f):
			
			try: # depending on the trace format
				tm, dir_size  = l.strip("\n").split(",")
			except:
				tm, dir_size, _ = l.strip("\n").split(",")

			tm = float(tm)
			dir_size = int(dir_size)
			size = abs(dir_size)
			direction = np.sign(dir_size)
			DIR_DIST.append(direction)
			if direction == 1:
				OUT_SIZE_DIST.append(size)
			else:
				IN_SIZE_DIST.append(size)
			tms.append(direction * tm)
		
		for i in range(len(tms) - 1):
			cur = tms[i]
			nxt = tms[i+1]
			tm_diff = round(abs(nxt) - abs(cur), 6)
			if np.sign(cur) != np.sign(nxt):
				DIFF_GAP_DIST.append(tm_diff)
			else:
				SAME_GAP_DIST.append(tm_diff)

	dist_all = {}
	dist_all["dir"] = {"v":[], "w":[]}
	dist_all["out_size"] = {"v":[], "w":[]}
	dist_all["in_size"] = {"v":[], "w":[]}
	dist_all["same_gap"] = {"v":[], "w":[]}
	dist_all["diff_gap"] = {"v":[], "w":[]}

	DIR_DIST = normalize_dist(Counter(DIR_DIST))
	OUT_SIZE_DIST = normalize_dist(Counter(OUT_SIZE_DIST))
	IN_SIZE_DIST = normalize_dist(Counter(IN_SIZE_DIST))
	DIFF_GAP_DIST = normalize_dist(Counter(DIFF_GAP_DIST))
	SAME_GAP_DIST = normalize_dist(Counter(SAME_GAP_DIST))	

	dist_all["dir"]["v"] = list(DIR_DIST.keys())
	dist_all["dir"]["w"] = list(DIR_DIST.values())

	dist_all["out_size"]["v"] = list(OUT_SIZE_DIST.keys())
	dist_all["out_size"]["w"] = list(OUT_SIZE_DIST.values())

	dist_all["in_size"]["v"] = list(IN_SIZE_DIST.keys())
	dist_all["in_size"]["w"] = list(IN_SIZE_DIST.values())

	dist_all["same_gap"]["v"] = list(SAME_GAP_DIST.keys())
	dist_all["same_gap"]["w"] =	list(SAME_GAP_DIST.values())

	dist_all["diff_gap"]["v"] = list(DIFF_GAP_DIST.keys())
	dist_all["diff_gap"]["w"] =	list(DIFF_GAP_DIST.values())

	pickle.dump(dist_all, open(output_file, "wb" ))


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--input',
						type=str,
						required=True,
						metavar='<path/to/input_trace>',
						help='Path to the directory where the orginal traces are stored.')

	parser.add_argument('-o', '--output',
						type=str,
						required=True,
						metavar='<path/to/output_db>',
						help='Path to the file where packet dist will be stored.')

	args = parser.parse_args()
	gen_dist_db(args.input, args.output)

