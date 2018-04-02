#!/usr/bin/python
# -*- coding: utf-8 -*-

# autonomous systems parser
# usage: python scriptname.py --as=AS28890 or python scriptname.py --as=AS28890,AS12668

# install additionals:
# apt-get update
# apt-get install python-pip
# pip install netaddr

# check:
# apt-cache show python-pip

import sys
import netaddr
import subprocess
import optparse

skipIPv6 = True

# RIR - Regional Internet Registry
# RIRs = [
# 	'afrinic', # AFRINIC  (African Network Information Center)                     http://www.afrinic.net/ whois.afrinic.net
# 	'arin',    # APNIC    (Asia-Pacific Network Information Centre)                http://www.apnic.net/   whois.apnic.net
# 	'apnic',   # ARIN     (American Registry for Internet Numbers)                 http://www.arin.net/    whois.arin.net
# 	'lacnic',  # LACNIC   (Latin America and Caribbean Network Information Centre) http://www.lacnic.net/  whois.lacnic.net
# 	'ripe'     # RIPE NCC (Réseaux IP Européens Network Coordination Centre)       http://www.ripe.net/    whois.ripe.net
# ]

tip_msg = 'specify --as=List of autonomous systems (one or more separated by comma without whitespaces or use \'\'). Example:'
tip_msg += 'python ' + sys.argv[0] + ' --as=AS28890 or python ' + sys.argv[0] + ' --as=AS28890,AS12668'

def parse_arguments():
	parser = optparse.OptionParser()
	parser.add_option("--as", dest="autonomousSystems",
	                  help="List of autonomous systems (one or more separated by comma without whitespaces or use '')")
	(options, args) = parser.parse_args()

	if not options.autonomousSystems:
		print tip_msg
		sys.exit()

	AS = [] # AS - autonomous systems
	AStmp = options.autonomousSystems.split(',')
	for system in AStmp:
		if not system.strip():
			continue
		if not system.strip().lower().startswith('as'):
			system = 'AS' + system.strip()
		AS.append(system)

	return AS

def parse_autonomous_systems(AS):
	output = ''
	for system in AS:
		output += subprocess.check_output("whois -ra -- '-T route,route6 -i origin " + system + "' | grep route | awk '{print$2}'", shell=True)
		# -r                     turn off recursive look-ups for contact information
		# -a                     also search all the mirrored databases
		# whois -ra -- '-T route,route6 -i origin AS28890' | grep route | awk '{print$2}	
		output += '\n'

	output = output.strip()
	if not output:
		return 'whois return empty answer'
		#sys.exit()

	subnets = []
	resultSubnets = []
	subnetsTmp = output.split('\n')
	for subnet in subnetsTmp:
		subnet = subnet.strip()
		if subnet and ('.' in subnet or ':' in subnet):
			if ':' not in subnet: # IPv4
				subnets.append(netaddr.IPNetwork(subnet))
		elif not skipIPv6: # IPv6
			print 'IPv6:' + subnet

	# merge networks
	subnets = netaddr.cidr_merge(subnets)

	for subnet in subnets:
		resultSubnets.append(str(subnet))

	#print 'result subnets:'
	#for subnet in resultSubnets:
	#	print subnet

	return '\n'.join(resultSubnets)

AS = parse_arguments()
if not AS:
	print tip_msg
	sys.exit()

result = parse_autonomous_systems(AS)
print result



# AS28890 # Insis
# AS12668 # Planeta

# vk.com # AS-VKONTAKTE
# AS47541
# AS47542
# AS28709 # not used

# ok.ru # mail.ru
# AS47764

# yandex
# AS13238
# AS20144
# AS43247
# AS202611

# facebook (ARIN)
# AS32934

# twitter (ARIN)
# AS13414
