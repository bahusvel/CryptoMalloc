#!/usr/bin/python3

import sys


maps = open("/proc/{}/maps".format(sys.argv[1]), mode='r')
mem = open("/proc/{}/mem".format(sys.argv[1]), mode='rb')
for line in maps.readlines():
	parts = line.strip("\n").split(" ")
	page_flags = parts[1]
	if page_flags.startswith("rw"):
		addr_range = parts[0].split("-")
		mapping = parts[-1]
		start_addr = int(addr_range[0], base=16)
		end_addr = int(addr_range[1], base=16)
		mem.seek(start_addr)
		data = mem.read(end_addr-start_addr)
		sys.stdout.buffer.write(data)
