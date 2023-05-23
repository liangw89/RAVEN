from trace_sim import *
import argparse
import shutil


def load_dist(dist_file_path):
	return pickle.load(open(dist_file_path, "rb"))


def write_trace(subflows, fout):
	tmp = ["{},{}\n".format(v[0], v[1]) for v in subflows]
	open(fout, "w").writelines(tmp)


def split_trace_real(fn, error_type, error_rate, pkt_dist):
	subflows_in = get_subflows_observed(fn)
	subflows_out = gen_subflow_with_recons_errrors(subflows_in, error_type, error_rate, pkt_dist)
	return subflows_out


def split_trace_sim(fn, error_type, error_rate, mig_freq, pkt_dist):
	subflows_in = get_subflow_sim_frequency(fn, mig_freq)
	subflows_out = gen_subflow_with_recons_errrors(subflows_in, error_type, error_rate, pkt_dist)
	return subflows_out


def split_trace_sampling(fn, missing_ratio):
	subflows = get_subflow_sampling(fn, missing_ratio)
	return subflows


def process_trace(dir_in, dir_out, method, error_type, error_rate, mig_freq, dist_path, rnd_seed=None):

	assert method in [METHOD_REAL, METHOD_SIM, METHOD_SAMPLE], """
	Incorrect method. Must be 0, 1 or 2 
	"""

	if rnd_seed:
		random.seed(rnd_seed)

	if os.path.exists(dir_out):
		shutil.rmtree(dir_out)
	os.mkdir(dir_out)

	if error_type == MISSING_ERROR:
		pkt_dist = None
	else:
		assert dist_path, """
		Please set the path to the packet dist file using -d;
		The dist file can be generated via utils/gen_dist.py
		"""
		pkt_dist = load_dist(dist_path)

	fs = sorted(os.listdir(dir_in))

	for _fn in fs:
		if _fn.startswith("."): continue
		fn = os.path.join(dir_in, _fn)

		if method == METHOD_REAL:
			_out = split_trace_real(fn, error_type, error_rate, pkt_dist)

		if method == METHOD_SIM:
			_out = split_trace_sim(fn, error_type, error_rate, mig_freq, pkt_dist)

		if method == METHOD_SAMPLE:
			_out = split_trace_sampling(fn, error_rate)

		fn = os.path.join(dir_out, _fn)
		write_trace(_out, fn)


def examples(fn):

	pkt_dist = load_dist("dist.db")

	"""
	Using subflows created by RAVEN 
	"""
	# Only using the first subflow (missing others with prob = 100%)
	split_trace_real(fn, MISSING_ERROR, 1, None)

	# Missing a subflow with prob = 10%
	split_trace_real(fn, MISSING_ERROR, 0.1, None)

	# Including a wrong subflow with prob = 10%
	split_trace_real(fn, WRONGLY_ERROR, 0.1, pkt_dist)

	# Including a wrong or missing a subflow with prob = 10%
	split_trace_real(fn, MIXED_ERROR, 0.1, pkt_dist)

	"""
	Using simulated subflows
	"""
	# Return the first subflow, migration freq = 10 pkts
	split_trace_sim(fn, MISSING_ERROR, 1, 10, None)

	# Missing a subflow with prob = 10%
	split_trace_sim(fn, MISSING_ERROR, 0.1, 10, None)

	# Including a wrong subflow with prob = 10%
	split_trace_sim(fn, WRONGLY_ERROR, 0.1, 10, pkt_dist)

	# Including a wrong or missing a subflow with prob = 10%
	split_trace_sim(fn, MIXED_ERROR, 0.1, 10, pkt_dist)



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
						help='Path to the directory where the split traces will be stored.')

	parser.add_argument('-m', '--method',
						type=int,
						required=True,
						default=0,
						metavar='<split/method>',
						help='Split based on real subflows (0), simulated split (1), or sampling (2)')

	parser.add_argument('-et', '--error_type',
						type=int,
						default=0,
						metavar='<error_type>',
						help='Error type: missing (0), wrongly included (1) or mixed both (2)')

	parser.add_argument('-er', '--error_rate',
						type=float,
						default=0.1,
						metavar='<error_rate>',
						help='Error rate 0 to 1')

	parser.add_argument('-f', '--freq',
						type=int,
						default=10,
						metavar='<mig_freq>',
						help='Migration frequency; -1 will enable random migration')


	parser.add_argument('-d', '--dist',
						type=str,
						default=None,
						metavar='<path/dist/db>',
						help='Path to the packet distirbution data')

	parser.add_argument('-rs', '--rnd_seed',
						type=int,
						default=None,
						metavar='<random_seed>',
						help='Set random seed')
	
	args = parser.parse_args()
	dir_in = args.input
	dir_out = args.output
	method = args.method
	error_type = args.error_type
	error_rate = args.error_rate
	mig_freq = args.freq
	dist_path = args.dist
	rnd_seed = args.rnd_seed

	process_trace(dir_in, dir_out, method, error_type, error_rate, mig_freq, dist_path, rnd_seed)


if __name__ == '__main__':
	main()

