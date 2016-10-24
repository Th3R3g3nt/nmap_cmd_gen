#########################
##
## NMAP command generator
## v0.7
## 
## Coded by Th3R3g3nt
##
#########################

import sys
import glob
import operator
import argparse
import subprocess 

from netaddr import *
import time, logging

def main():

	#Read the command line arguments
	parser = argparse.ArgumentParser(description='Nmap command generator by Th3_R3g3nt')
	parser.add_argument('-i','--input', nargs="+", type=str, required=True, help='Host list; one host or CIDR per line')
	parser.add_argument('-p','--project', type=str, required=True, help='Name of the project')
	parser.add_argument('-l','--longform', action='store_true', help='Long command format; each IP has it\' own command line')
	args = parser.parse_args()

	#Check if enough arguments
	if len(sys.argv) < 2:
		print parser.print_help()
		exit()
				
	args.input = reduce(operator.add, map(glob.glob, args.input))
		
	#Timestamp sync
	timenow = time.strftime("%Y_%m_%d--%H_%M_%S")
	ips = []

	logging.basicConfig(filename=args.project+'_'+timenow+'_nmap_cmd_gen.log',level=logging.DEBUG)
	logging.debug(' [ ] Processing '+str(len(args.input))+' files total')

	#Work through if multiple files are provided as target list
	for input_file_list in args.input:

		logging.debug(' [ ] --------------------')
		try:
			logging.debug(' [ ] Trying to open current_file '+input_file_list)
			current_file = open(input_file_list, "r")

		except:
			logging.debug(' [X] Failed to open current_file '+input_file_list)
			print "Can't open", input_file_list,"\n\nExiting"
			exit()

		logging.debug(' [ ] Current file is '+input_file_list)

		for line in current_file:
			try:
				lineitem = IPNetwork(line.strip())
				ips.append(lineitem)
			except:
				print "Exception in line item "+line+" and cannot be interpreted as IP or IP range"
				exit()
				
			#Populate all individual IPs.
			'''
			for ip in lineitem:
				if ip not in ips:
					ips.append(ip)
					#print "Added "+str(ip)
				else:
					print "Duplicate IP not added "+str(lineitem)+" as "+str(ip)
			'''
	
	#Save the IP list
	try:
		logging.debug(' [ ] Trying to open IP list output file')
		output_file = open(args.project+'_'+timenow+'_ip_list.txt', "wb")
		for i in ips:
			output_file.write(str(i)+'\n')
		output_file.close()
	except:
		logging.debug(' [X] Failed to open IP list output for writing')
		print "Can't open IP list output file\n\nExiting"
		exit()
		
	#Result file

	logging.debug(' [ ] Trying to open resulting .sh file')
	output_file = open(args.project+'_'+timenow+'_nmap_discovery_command.sh', 'wb')
	input_file = open(args.project+'_'+timenow+'_ip_list.txt', "rb")
	
	#In case we need 1 ip - 1 cmd relation
	## REVIEW BELOW
	'''	if args.longform:
		input_file = open(args.project+'_'+timenow+'_ip_list.txt', "rb")
		output_file.write('#/bin/sh\n')



		output_file.write('#Web Ports\n')		
		for i in input_file:
			file_item = str(i.replace(".","_").replace("/","--")).strip()
			output_file.write('nmap -sSV -Pn -R --max-retries 2 --min-parallelism 40 -p80,443,8080,8081,8443 -T3 -vvv -oA '+args.project+'_'+timenow+'__'+file_item+'_web_portscan '+i.strip()+' >'+args.project+'_'+timenow+'__'+file_item+'_web_portscan--raw.txt\n')
			
		output_file.write('#Common TCP Ports\n')
		input_file.seek(0,0)
		for i in input_file:
			file_item = str(i.replace(".","_").replace("/","--")).strip()
			output_file.write('nmap -sSV -Pn -R --max-retries 2 --min-parallelism 40 -T3 -vvv -oA '+args.project+'_'+timenow+'__'+file_item+'_common_portscan '+i.strip()+' >'+args.project+'_'+timenow+'__'+file_item+'_common_portscan--raw.txt\n')
		
		output_file.write('#SCADA  TCP Ports, ICS Network\n')
		input_file.seek(0,0)
		for i in input_file:
			file_item = str(i.replace(".","_").replace("/","--")).strip()
			output_file.write('nmap -sTV -Pn -R --max-retries 2 --max-parallelism 30 -p 80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1048,1049,1053,1054,1056,1064,1065,2967,3703,17,808,3689,1031,1044,1071,5901,100,9102,1039,2869,4001,5120,8010,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,1032,1050,6112,3690,1521,2161,1080,6002,2401,902,4045,787,7937,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,3,593,2301,3268,7938,1022,1234,1035,1036,1037,1074,8002,9001,464,497,1935,2003,6666,102,502,1089,1090,1091,1541,4840,5052,5065,5450,10307,10311,10364,10365,10407,10409,10410,10412,10414,10415,10428,10431,10432,10447,10449,10450,11001,12135,12136,12137,12316,12645,12647,12648,13722,13724,13782,13783,18000,20000,34962,34963,34964,38000,38001,38011,38012,38014,38015,38200,38210,38301,38400,38589,38593,38600,38700,38971,39129,39278,44818,45678,50001,50002,50003,50004,50005,50006,50007,50008,50009,50010,50011,50012,50013,50014,50015,50016,50018,50019,50020,50025,50026,50027,50028,50110,50111,55555,56001,56002,56003,56004,56005,56006,56007,56008,56009,56010,56011,56012,56013,56014,56015,56016,56017,56018,56019,56020,56021,56022,56023,56024,56025,56026,56027,56028,56029,56030,56031,56032,56033,56034,56035,56036,56037,56038,56039,56040,56041,56042,56043,56044,56045,56046,56047,56048,56049,56050,56051,56052,56053,56054,56055,56056,56057,56058,56059,56060,56061,56062,56063,56064,56065,56066,56067,56068,56069,56070,56071,56072,56073,56074,56075,56076,56077,56078,56079,56080,56081,56082,56083,56084,56085,56086,56087,56088,56089,56090,56091,56092,56093,56094,56095,56096,56097,56098,56099,62900,62911,62924,62930,62938,62956,62957,62963,62981,62982,62985,62992,63012,63027,63028,63029,63030,63031,63032,63033,63034,63035,63036,63041,63075,63079,63082,63088,63094,65443 -T3 -vvv -oA '+args.project+'_'+timenow+'__'+file_item+'_tcp_scada_portscan_ICS_internal '+i.strip()+' >'+args.project+'_'+timenow+'__'+file_item+'_tcp_scada_portscan_ICS_internal--raw.txt\n')

		output_file.write('#Smart  UDP Ports, ICS Network\n')
		input_file.seek(0,0)
		for i in input_file:
			file_item = str(i.replace(".","_").replace("/","--")).strip()
			output_file.write('nmap -sU -Pn -R --max-retries 2 --max-parallelism 30 -pU:631,161,137,123,138,1434,445,135,67,53,139,500,68,520,1900,4500,514,49152,162,69,5353,111,49154,1701,998,996,997,999,3283,49153,1812,136,2222,2049,32768,5060,1025,1433,3456,80,20031,1026,7,1646,1645,1089,1090,1091,1541,4000,5050,5051,11001,20000,34962,34963,34964,34980,44818,45678,47808,50020,50021,55000,55001,55002,55003,55555 -T3 -vvv -oA '+args.project+'_'+timenow+'__'+file_item+'_udp_scada_portscan_ICS_internal '+i.strip()+' >'+args.project+'_'+timenow+'__'+file_item+'_udp_scada_portscan_ICS_internal--raw.txt\n')

		output_file.write('#All TCP Ports\n')
		input_file.seek(0,0)
		for i in input_file:
			file_item = str(i.replace(".","_").replace("/","--")).strip()
			output_file.write('nmap -sSV -Pn -R --max-retries 2 --min-parallelism 50  -p0-65535 -T3 -vvv -oA '+args.project+'_'+timenow+'__'+file_item+'_full_portscan '+i.strip()+' >'+args.project+'_'+timenow+'__'+file_item+'_full_portscan--raw.txt\n')


		output_file.close()
		exit()
	'''
	
	#Short format, all IPs will go into a big pool
	input_file.seek(0,0)
	
	output_file.write('#/bin/sh\n')
	output_file.write('#Ping Sweep\n')
	output_file.write('nmap -sn -PE -R --max-retries 0 -T2 -vvv -oA '+args.project+'_'+timenow+'_pingsweep -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_pingsweep--raw.txt\n')

	output_file.write('#MS DC TCP Ports\n')
	output_file.write('nmap -sSV -Pn -R --max-retries 0 --min-hostgroup 130 -p88,389,636 -T3 -vvv -oA '+args.project+'_'+timenow+'_MS_DC_portscan -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_MS_DC_portscan--raw.txt\n')
	
	output_file.write('#MS Client TCP Ports\n')
	output_file.write('nmap -sSV -Pn -R --max-retries 0 --min-hostgroup 130 -p445 -T3 -vvv -oA '+args.project+'_'+timenow+'_MS_client_portscan -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_MS_client_portscan--raw.txt\n')
	
	output_file.write('#Web Ports\n')
	output_file.write('nmap -sSV -Pn -R --max-retries 2 --min-parallelism 50 --min-hostgroup 130 -p80,443,8080,8081,8443 -T3 -vvv -oA '+args.project+'_'+timenow+'_web_portscan -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_web_portscan--raw.txt\n')
	
	output_file.write('\n#Common TCP Ports\n')
	output_file.write('nmap -sSV -Pn -R --max-retries 2 --min-parallelism 50 --min-hostgroup 130 -T3 -vvv -oA '+args.project+'_'+timenow+'_common_portscan -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_common_portscan--raw.txt\n')
	
	output_file.write('\n#SCADA  TCP Ports\n')
	output_file.write('nmap -sSV -Pn -R --max-retries 2 --min-parallelism 50 --min-hostgroup 130 -p 80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1048,1049,1053,1054,1056,1064,1065,2967,3703,17,808,3689,1031,1044,1071,5901,100,9102,1039,2869,4001,5120,8010,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,1032,1050,6112,3690,1521,2161,1080,6002,2401,902,4045,787,7937,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,3,593,2301,3268,7938,1022,1234,1035,1036,1037,1074,8002,9001,464,497,1935,2003,6666,102,502,1089,1090,1091,1541,4840,5052,5065,5450,10307,10311,10364,10365,10407,10409,10410,10412,10414,10415,10428,10431,10432,10447,10449,10450,11001,12135,12136,12137,12316,12645,12647,12648,13722,13724,13782,13783,18000,20000,34962,34963,34964,38000,38001,38011,38012,38014,38015,38200,38210,38301,38400,38589,38593,38600,38700,38971,39129,39278,44818,45678,50001,50002,50003,50004,50005,50006,50007,50008,50009,50010,50011,50012,50013,50014,50015,50016,50018,50019,50020,50025,50026,50027,50028,50110,50111,55555,56001,56002,56003,56004,56005,56006,56007,56008,56009,56010,56011,56012,56013,56014,56015,56016,56017,56018,56019,56020,56021,56022,56023,56024,56025,56026,56027,56028,56029,56030,56031,56032,56033,56034,56035,56036,56037,56038,56039,56040,56041,56042,56043,56044,56045,56046,56047,56048,56049,56050,56051,56052,56053,56054,56055,56056,56057,56058,56059,56060,56061,56062,56063,56064,56065,56066,56067,56068,56069,56070,56071,56072,56073,56074,56075,56076,56077,56078,56079,56080,56081,56082,56083,56084,56085,56086,56087,56088,56089,56090,56091,56092,56093,56094,56095,56096,56097,56098,56099,62900,62911,62924,62930,62938,62956,62957,62963,62981,62982,62985,62992,63012,63027,63028,63029,63030,63031,63032,63033,63034,63035,63036,63041,63075,63079,63082,63088,63094,65443 -T3 -vvv -oA '+args.project+'_'+timenow+'_tcp_scada_portscan -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_tcp_scada_portscan--raw.txt\n')
	
	output_file.write('\n#Smart  UDP Ports\n')
	output_file.write('nmap -sU -Pn -R --max-retries 2 --min-parallelism 50 --min-hostgroup 130 -pU:631,161,137,123,138,1434,445,135,67,53,139,500,68,520,1900,4500,514,49152,162,69,5353,111,49154,1701,998,996,997,999,3283,49153,1812,136,2222,2049,32768,5060,1025,1433,3456,80,20031,1026,7,1646,1645,1089,1090,1091,1541,4000,5050,5051,11001,20000,34962,34963,34964,34980,44818,45678,47808,50020,50021,55000,55001,55002,55003,55555 -T3 -vvv -oA '+args.project+'_'+timenow+'_udp_scada_portscan -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_udp_scada_portscan--raw.txt\n')

	output_file.write('\n#SCADA  TCP Ports, ICS Network\n')
	output_file.write('nmap -sTV -Pn -R --max-retries 2 --max-parallelism 30 --max-hostgroup 1 -p 80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1048,1049,1053,1054,1056,1064,1065,2967,3703,17,808,3689,1031,1044,1071,5901,100,9102,1039,2869,4001,5120,8010,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,1032,1050,6112,3690,1521,2161,1080,6002,2401,902,4045,787,7937,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,3,593,2301,3268,7938,1022,1234,1035,1036,1037,1074,8002,9001,464,497,1935,2003,6666,102,502,1089,1090,1091,1541,4840,5052,5065,5450,10307,10311,10364,10365,10407,10409,10410,10412,10414,10415,10428,10431,10432,10447,10449,10450,11001,12135,12136,12137,12316,12645,12647,12648,13722,13724,13782,13783,18000,20000,34962,34963,34964,38000,38001,38011,38012,38014,38015,38200,38210,38301,38400,38589,38593,38600,38700,38971,39129,39278,44818,45678,50001,50002,50003,50004,50005,50006,50007,50008,50009,50010,50011,50012,50013,50014,50015,50016,50018,50019,50020,50025,50026,50027,50028,50110,50111,55555,56001,56002,56003,56004,56005,56006,56007,56008,56009,56010,56011,56012,56013,56014,56015,56016,56017,56018,56019,56020,56021,56022,56023,56024,56025,56026,56027,56028,56029,56030,56031,56032,56033,56034,56035,56036,56037,56038,56039,56040,56041,56042,56043,56044,56045,56046,56047,56048,56049,56050,56051,56052,56053,56054,56055,56056,56057,56058,56059,56060,56061,56062,56063,56064,56065,56066,56067,56068,56069,56070,56071,56072,56073,56074,56075,56076,56077,56078,56079,56080,56081,56082,56083,56084,56085,56086,56087,56088,56089,56090,56091,56092,56093,56094,56095,56096,56097,56098,56099,62900,62911,62924,62930,62938,62956,62957,62963,62981,62982,62985,62992,63012,63027,63028,63029,63030,63031,63032,63033,63034,63035,63036,63041,63075,63079,63082,63088,63094,65443 -T3 -vvv -oA '+args.project+'_'+timenow+'_tcp_scada_portscan_ICS_internal -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_tcp_scada_portscan_ICS_internal--raw.txt\n')

	output_file.write('\n#Smart  UDP Ports, ICS Network\n')
	output_file.write('nmap -sU -Pn -R --max-retries 2 --max-parallelism 30 --max-hostgroup 1 -pU:631,161,137,123,138,1434,445,135,67,53,139,500,68,520,1900,4500,514,49152,162,69,5353,111,49154,1701,998,996,997,999,3283,49153,1812,136,2222,2049,32768,5060,1025,1433,3456,80,20031,1026,7,1646,1645,1089,1090,1091,1541,4000,5050,5051,11001,20000,34962,34963,34964,34980,44818,45678,47808,50020,50021,55000,55001,55002,55003,55555 -T3 -vvv -oA '+args.project+'_'+timenow+'_udp_scada_ICS_internal -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_udp_scada_portscan_ICS_internal--raw.txt\n')
	
	output_file.write('\n#All TCP Ports\n')
	output_file.write('nmap -sSV -Pn -R --max-retries 2 --min-parallelism 50 --min-hostgroup 256 -p0-65535 -T3 -vvv -oA '+args.project+'_'+timenow+'_full_portscan -iL '+args.project+'_'+timenow+'_ip_list.txt >'+args.project+'_'+timenow+'_full_portscan--raw.txt\n')
	
	output_file.close()
	exit()

if __name__ == "__main__":
	main()