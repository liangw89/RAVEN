import os
import sys
import shutil
import numpy as np 
import random
import pickle
import pickle
import configparser
import glob

# Enable this line only for testing 
# random.seed(100)

MISSING_ERROR = 0
WRONGLY_ERROR = 1
MIXED_ERROR = 2

METHOD_REAL = 0
METHOD_SIM = 1
METHOD_SAMPLE = 2


def sim_subflow(subflow_in, pkt_dist):
	# Subflow format: [(time, dir_size)]
	subflow_out = [subflow_in[0]]
	st_time = subflow_in[0][0]
	ed_time = subflow_in[-1][0]
	prev_time = st_time
	cur_time = st_time
	prev_dir = np.sign(subflow_in[0][1])

	while cur_time <= ed_time:
		cur_dir = random.choices(pkt_dist["dir"]["v"], pkt_dist["dir"]["w"])[0]

		if cur_dir == -1:
			cur_size = random.choices(pkt_dist["in_size"]["v"], pkt_dist["in_size"]["w"])[0]
		else:
			cur_size = random.choices(pkt_dist["out_size"]["v"], pkt_dist["out_size"]["w"])[0]

		if cur_dir == prev_dir:
			cur_time = prev_time + random.choices(pkt_dist["same_gap"]["v"], pkt_dist["same_gap"]["w"])[0]
		else:
			cur_time = prev_time + random.choices(pkt_dist["diff_gap"]["v"], pkt_dist["diff_gap"]["w"])[0]

		if cur_time > ed_time:
			break

		prev_time = cur_time
		prev_dir = cur_dir
		pkt = (cur_time, cur_dir * cur_size)
		subflow_out.append(pkt)

	subflow_out.append(subflow_in[-1])
	return subflow_out


def get_subflows_observed(fn):

	"""
	The subflows observed by the adversary based on five tuples.
	"""

	tmp = [v.strip("\n") for v in open(fn).readlines()]

	assert len(tmp[0].split(",")) == 3, """
	The trace format or trace delimiter is incorrect
	Excepted format (type = 0): time, size * direction, subflowNo
	Excepted delimiter: comma
	"""

	# Get idx. of subflows from real traffic
	subflow_idx = set([int(v.strip("\n").split(",")[-1]) for v in tmp])

	sf_dict = {}
	for k in subflow_idx: sf_dict[k] = []
	for l in tmp:
		tm, size_dr, k = l.strip("\n").split(",")
		sf_dict[int(k)].append((float(tm), int(size_dr)))

	subflows = []
	for k in range(len(sf_dict)):
		subflows.append(sf_dict[k])

	return subflows


def get_subflow_sim_frequency(fn, mig_freq:int):
	"""
	The simulated subflows generated based on a given migration frequency.
	"""

	tmp = np.array(open(fn).readlines())
	pkt_no = len(tmp)

	# If mig_freq is -1, perform random migration between 1 to 20 
	# outgoing pkts per migration
	if mig_freq == -1: mig_freq = random.sample(list(range(1, 21)), 1)[0]

	# Find idx of all outgoing packets (direction = 1)
	_dir = np.sign([float(v.split(",")[1]) for v in tmp])
	split_idx = np.where(_dir[:] == 1)

	# Split the flow into segments based on the outgoing packets
	flow_segs = np.split(tmp, split_idx[0][1:])

	# Get subflows based on the migration threshold 
	subflows = []
	cnt = 0
	_sf = []
	for seg in flow_segs:
		# Convert format to type 1
		seg = [(float(v.split(",")[0]), int(v.split(",")[1])) for v in seg]
		_sf += seg
		cnt += 1
		if cnt < mig_freq:
			continue
		subflows.append(_sf)
		cnt = 0
		_sf = []
		if mig_freq == 0: mig_freq = random.sample(list(range(1, 20)), 1)[0]

	# The remaining packets 
	if (sum([len(v) for v in subflows]) != pkt_no):
		subflows.append(_sf)

	# Check the correctness of flow splitting
	assert sum([len(v) for v in subflows]) == pkt_no, "{}: Incorrect flow splitting".format(fn)

	return subflows


def get_subflow_sampling(fn, missing_ratio):
	"""
	
	"""
	tmp = np.array(open(fn).readlines())
	pkt_no = len(tmp)

	subflows = []
	idx = random.sample(list(range(pkt_no)), round(pkt_no - pkt_no * missing_ratio))
	idx = sorted(idx)
	for i in idx:
		subflows.append((float(tmp[i].split(",")[0]), int(tmp[i].split(",")[1])))

	# Return a list, not a nested list
	return subflows
 

def gen_subflow_with_recons_errrors(subflows_in, error_type, error_rate, pkt_dist:dict=None):

	# !!! The first subflow is always included because it is associated with the connection handshakes.
	subflows_out = subflows_in[0]

	# If only 1 subflow, no location to inject errors; use the subflow as it is.
	if len(subflows_in) == 1:
		return subflows_out

	assert error_type in [MISSING_ERROR, WRONGLY_ERROR, MIXED_ERROR], """Incorrect error type:
	Can only be 0 (Missing), 1 (Wrongly), or 2 (Both)
	"""

	# Generate the locations where errors would be introduced
	error_list = [random.random() for v in range(len(subflows_in) - 1)]
	if len(error_list) == 1: idx = 0
	else: idx = random.randint(0, len(error_list) - 1) 
	error_list[idx] = error_rate / 2 # At least 1 error

	for idx in range(len(error_list)):
		sf = subflows_in[idx+1]
		if error_list[idx] <= error_rate:

			# Error type: Mixed missing and wrongly
			if error_type == MIXED_ERROR:
				error_type = [MISSING_ERROR, WRONGLY_ERROR][random.randint(0, 1)]

			# Error type: Wrongly
			if error_type == WRONGLY_ERROR:
				sf = sim_subflow(sf, pkt_dist)

			# Error type: Missing
			if error_type == MISSING_ERROR:
				sf = []

		subflows_out += sf

	return subflows_out

