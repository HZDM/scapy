#!/usr/local/bin/python

from scapy.all import *
import datetime
from datetime import timedelta

global ip_addr, dport, report_interval, tp_1_list, tp_2_list, cl_list, min_list_len

# configure
ip_addr = '192.168.1.101'

dport = 5559

report_interval = 100  # in ms

tp_1_list = ['\x5a', '\xa1', '\xd4', '\x4c']
tp_2_list = ['\xb2', '\x42', '\x8b', '\xe7']
cl_list   = ['\x00', '\xff', '\xda', '\xb3']

min_list_len = min(len(tp_1_list), len(tp_2_list), len(cl_list))

#func

global ip, tcp, current_time, last_report_time, inject_cnt
if __name__ == "__main__":

	ip 	= IP()
	ip.dst = ip_addr
	# ip.display()

	# sync 
	tcp = TCP()
	tcp.dport = dport
	tcp.flags = "S"
	tcp.options = [("MSS", 1460)]
	# tcp.display()

	#receive syn+ack
	rcv_packet = sr1(ip/tcp)
	# rcv_packet.show()

	tcp.flags = "A"
	tcp.seq = 1
	tcp.ack = rcv_packet.seq + 1
	tcp.options = []

	rcv_packet = sr1(ip/tcp)


	current_time = datetime.datetime.now()
	last_report_time = current_time
	inject_cnt = 0
	while 1:
		tcp.flags = "A"
		tcp.seq = rcv_packet.ack
		tcp.ack = rcv_packet.seq + rcv_packet.len - 20 - rcv_packet.dataofs * 4 

		current_time = datetime.datetime.now()
		delta = current_time - last_report_time
		last_report_time = current_time
		if int(delta.total_seconds()*1000) > report_interval:
			
			tp_1 = tp_1_list[inject_cnt]
			tp_2 = tp_2_list[inject_cnt]
			cl   = cl_list[inject_cnt]
			option_content = "\x60\x06\x00\x01\x00\x02" + tp_1 + tp_2 + "\x02\x00\x01" + cl

			tcp.options = [("TEST", option_content)]

			inject_cnt = (inject_cnt + 1) % min_list_len
			# print inject_cnt
			pass
		else:
			tcp.options = []
			pass

		rcv_packet = sr1(ip/tcp, timeout = 2)

		if rcv_packet is None:
			break
			pass
		pass

	print "receive end!"

	pass