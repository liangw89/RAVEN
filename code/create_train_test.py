import os
import sys
import shutil
import random
import configparser
import argparse

config = configparser.ConfigParser()
config.read('config.ini')

num_unmon_site = config.getint('Trace', 'num_unmon_site')
num_mon_site = config.getint('Trace', 'num_mon_site')
num_mon_inst = config.getint('Trace', 'num_mon_inst')
mon_test_ratio = config.getfloat('Trace', 'mon_test_ratio') # % of insts for testing
unmon_test_ratio = config.getfloat('Trace', 'unmon_test_ratio')

def get_filename_delimiter(fn):
	if "-" in fn: return "-"
	if "_" in fn: return "_"
	raise Exception("Unknown filename delimiter")


def train_test_split(dir_in, dir_out, rnd_seed=None):
	if rnd_seed:
		random.seed(rnd_seed)

	fs = sorted(os.listdir(dir_in))
	filename_delimiter = get_filename_delimiter(fs[0])


	mon_set_all = set()
	unmon_set_all = set()
	for _fn in fs:
		if _fn.startswith("."): continue
		site_no, inst_no = _fn.split(filename_delimiter)
		site_no = int(site_no)
		unmon_range = range(num_mon_site, num_mon_site + num_unmon_site)
		if site_no < num_mon_site:
			mon_set_all.add(_fn)

		if site_no in unmon_range:
			unmon_set_all.add(_fn)

	mon_test = set()
	for i in range(num_mon_site):
		for j in random.sample(list(range(num_mon_inst)), int(num_mon_inst * mon_test_ratio)):
			mon_test.add("{}{}{}".format(i, filename_delimiter, j))
	mon_train = mon_set_all - mon_test


	unmon_test = random.sample(unmon_set_all, int(num_unmon_site * unmon_test_ratio))
	unmon_test = set(unmon_test)
	unmon_train = unmon_set_all - unmon_test

	# print (len(mon_set_all), len(unmon_set_all), len(mon_train), len(mon_test), len(unmon_train), len(unmon_test))

	if os.path.exists(dir_out):
		shutil.rmtree(dir_out)
	os.mkdir(dir_out)

	os.mkdir("{}/mon".format(dir_out))
	os.mkdir("{}/unmon".format(dir_out))
	os.mkdir("{}/mon_tr".format(dir_out))
	os.mkdir("{}/mon_te".format(dir_out))
	os.mkdir("{}/unmon_tr".format(dir_out))
	os.mkdir("{}/unmon_te".format(dir_out))

	for fn in mon_set_all:
		shutil.copy(os.path.join(dir_in, fn), os.path.join(dir_out, "mon"))

	for fn in unmon_set_all:
		shutil.copy(os.path.join(dir_in, fn), os.path.join(dir_out, "unmon"))

	for fn in mon_train:
		shutil.copy(os.path.join(dir_in, fn), os.path.join(dir_out, "mon_tr"))

	for fn in mon_test:
		shutil.copy(os.path.join(dir_in, fn), os.path.join(dir_out, "mon_te"))

	for fn in unmon_train:
		shutil.copy(os.path.join(dir_in, fn), os.path.join(dir_out, "unmon_tr"))

	for fn in unmon_test:
		shutil.copy(os.path.join(dir_in, fn), os.path.join(dir_out, "unmon_te"))


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--input',
						type=str,
						required=True,
						metavar='<path/to/input_trace>',
						help='Path to the directory where the orginal traces are stored.')

	parser.add_argument('-o', '--output',
						type=str,
						required=True,
						metavar='<path/to/output_trace>',
						help='Path to the directory where the processed traces will be stored.')

	parser.add_argument('-rs', '--rnd_seed',
						type=int,
						default=None,
						metavar='<random_seed>',
						help='Set random seed')

	args = parser.parse_args()
	dir_in = args.input
	dir_out = args.output
	rnd_seed = args.rnd_seed

	train_test_split(dir_in, dir_out, rnd_seed)

if __name__ == '__main__':
	main()
