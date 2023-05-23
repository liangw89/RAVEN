import argparse
import glob
import os
import shutil
import numpy as np

def trace_format_conversion(dir_in, dir_out, trace_delimiter, filename_delimiter, remove_size):

	assert trace_delimiter in ["c", "s", "t"], """
	Incorrect trace delimiter type":
	Must be: c (comma), t (tab), or s (space)
	"""

	assert filename_delimiter in ["_", "-"], """
	Incorrect filename delimiter type":
	Must be: "_" or "-"
	"""

	if os.path.exists(dir_out):
		shutil.rmtree(dir_out)
	os.mkdir(dir_out)

	fs = sorted(os.listdir(dir_in))
	for _fn in fs:
		if _fn.startswith("."): continue
		fn_in = os.path.join(dir_in, _fn)
		tmp = [v.strip("\n").split(",") for v in open(fn_in, "r").readlines()]
		if trace_delimiter == "c":
			trace_delimiter = ","
		if trace_delimiter == "t":
			trace_delimiter = "\t"
		if trace_delimiter == "s":
			trace_delimiter = ' '

		if remove_size:
			tmp = ["{}{}{}\n".format(v[0], trace_delimiter, np.sign(float(v[1]))) for v in tmp]
		else:
			tmp = ["{}{}{}\n".format(v[0], trace_delimiter, v[1]) for v in tmp]
		
		fn_out = os.path.join(dir_out, _fn.replace("_", filename_delimiter))
		open(fn_out, "w").writelines(tmp)


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
						help='Path to the directory where the processed traces are stored.')

	parser.add_argument('-td', '--trace_delimiter',
						type=str,
						default="c",
						metavar='<output/trace/delimiter>',
						help='Trace delimiter: c (comma), t (tab), or s (space) ')

	parser.add_argument('-fd', '--filename_delimiter',
						type=str,
						default='_',
						metavar='<output/trace_name/delimiter>',
						help='Filename delimiter: "_" or "-"')

	parser.add_argument('-ns', '--no_size',
						action='store_true',
						help='If the flag exists, remove the size information; default is false')

	args = parser.parse_args()

	dir_in = args.input
	dir_out = args.output
	trace_delimiter = args.trace_delimiter 
	filename_delimiter = args.filename_delimiter
	remove_size = args.no_size

	trace_format_conversion(dir_in, dir_out, trace_delimiter, filename_delimiter, remove_size)

if __name__ == '__main__':
	main()
