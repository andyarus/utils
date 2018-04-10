#!/usr/bin/python
# -*- coding: utf-8 -*-

# autonomous systems parser (ASN - autonomous system number) for route, route6 objects
# usage: python scriptname.py --asn=AS28890 or python scriptname.py --asn=AS28890,AS12668

# install additionals:
# apt-get update
# apt-get install python-pip
# pip install netaddr (pip --proxy=host:port install netaddr)

# check:
# apt-cache show python-pip

# RIR - Regional Internet Registry
# RIRs = [
# 	'afrinic', # AFRINIC  (African Network Information Center)                     http://www.afrinic.net/ whois.afrinic.net
# 	'arin',    # APNIC    (Asia-Pacific Network Information Centre)                http://www.apnic.net/   whois.apnic.net
# 	'apnic',   # ARIN     (American Registry for Internet Numbers)                 http://www.arin.net/    whois.arin.net
# 	'lacnic',  # LACNIC   (Latin America and Caribbean Network Information Centre) http://www.lacnic.net/  whois.lacnic.net
# 	'ripe'     # RIPE NCC (Réseaux IP Européens Network Coordination Centre)       http://www.ripe.net/    whois.ripe.net
# ]

import sys
import optparse
import netaddr
import requests, json
import syslog
import re

skipIPv6 = True
useProxy = False
proxy = {}
proxy['user'] = ''
proxy['password'] = ''
proxy['host'] = ''
proxy['port'] = int()
proxies = {}

tipMsg = 'specify --asn=List of autonomous systems numbers (one or more separated by comma without whitespaces or use \'\'). Example:'
tipMsg += 'python ' + sys.argv[0] + ' --asn=AS28890 or python ' + sys.argv[0] + ' --asn=\'AS28890,AS12668\''
tipMsgProxy = 'you must specify proxy: --proxy=host:port or --proxy=user:password@host:port'

def parseArguments():
	parser = optparse.OptionParser()
	parser.add_option("--asn", dest="autonomousSystems",
					help="List of autonomous systems (one or more separated by comma without whitespaces or use '')")
	parser.add_option("--db", dest="db",
					help="database source(s)")
	parser.add_option("--proxy", dest="proxy",
					help="proxy (host:port or user:password@host:port). only http(s)")
	(options, args) = parser.parse_args()

	return options

def mergeSubnets(messSubnets):
	subnets = []
	for subnet in messSubnets:
		subnet = subnet.strip()
		if subnet and ('.' in subnet or ':' in subnet):
			if ':' not in subnet: # IPv4
				subnets.append(netaddr.IPNetwork(subnet))
			elif not skipIPv6: # IPv6
				print 'IPv6:' + subnet
				syslog.syslog('IPv6:%s' % subnet)

	# merge networks
	subnets = netaddr.cidr_merge(subnets)

	resultSubnets = []
	for subnet in subnets:
		resultSubnets.append(str(subnet))

	return resultSubnets

def parseProxies(proxyStr, proxy):
	""" parse --proxy """
	if proxyStr:
		proxyStr = proxyStr.strip()
		if '@' in proxyStr:
			proxyStr = proxyStr.replace('@', ':')
		proxyParts = proxyStr.split(':')
		if len(proxyParts) >= 4:
			proxy['user'] = proxyParts[0]
			proxy['password'] = proxyParts[1]
			proxy['host'] = proxyParts[2]
			if proxyParts[3]:
				proxy['port'] = int(proxyParts[3])
		elif len(proxyParts) >= 2:
			proxy['host'] = proxyParts[0]
			if proxyParts[1]:
				proxy['port'] = int(proxyParts[1])

	if proxy['host'] and proxy['port']:
		return createRequestsProxies(proxy)
	else:
		return {}

def createRequestsProxies(proxy):
	proxies = {}
	if proxy['user'] and proxy['password']:
		proxies['http'] = 'http://%s:%s@%s:%d/' % (proxy['user'], proxy['password'], proxy['host'], proxy['port'])
		proxies['https'] = 'https://%s:%s@%s:%d/' % (proxy['user'], proxy['password'], proxy['host'], proxy['port'])
	else:
		proxies['http'] = 'http://%s:%d/' % (proxy['host'], proxy['port'])
		proxies['https'] = 'https://%s:%d/' % (proxy['host'], proxy['port'])

	return proxies

def getRoutesByAutonomousSystems(autonomousSystems, dbSource, proxies):
	"""
	whois -ra -- '-T route,route6 -i origin AS28890' | grep route | awk '{print$2}
	-r    turn off recursive look-ups for contact information
	-a    also search all the mirrored databases
	"""
	routes = []
	if dbSource:
		dbSource = dbSource.upper()
	for system in autonomousSystems:
		routesTmp = []
		if dbSource == 'RIPE':
			api_url = 'http://rest.db.ripe.net/search.json?query-string=%s&inverse-attribute=origin' % system
			# api https://github.com/RIPE-NCC/whois/wiki/WHOIS-REST-API-search
			try:
				r = requests.get(api_url, proxies=proxies)
			except Exception, e:
				syslog.syslog('request to %s failed:%s' % (api_url, e))
				return []

			if r.status_code != 200:
				syslog.syslog('request to %s failed[%d]:%s' % (api_url, r.status_code, r.reason))
				return []

			answer = r.json()
			objects = answer['objects']['object']
			for obj in objects:
				if 'route' not in obj['type'] or 'route6' not in obj['type']:
					pass
				attributes = obj['primary-key']['attribute']
				for attribute in attributes:
					if attribute['name'] == 'route':
						routesTmp.append(attribute['value'])
					elif not skipIPv6 and attribute['name'] == 'route6':
						routesTmp.append(attribute['value'])

		else:
			radb_url = 'http://radb.net/query/'
			data = { 'advanced_query' : '1', 'keywords' : system, 'query' : 'Query', '-T option' : '', 'ip_option' : '', '-i' : '1', '-i option' : 'origin', '-r' : '1' }
			# -i inverse query by: origin # -r turn off recursive lookups
			try:
				r = requests.post(radb_url, data=data, proxies=proxies)
			except Exception, e:
				syslog.syslog('request to %s failed:%s' % (radb_url, e))
				return []

			if r.status_code != 200:
				syslog.syslog('request to %s failed[%d]:%s' % api_url, r.status_code, response.reason)
				return []

			routesTmp = re.findall('%s:\s*([^<]+)<' % ('route' if skipIPv6 else 'route6?') , r.text)

		routes.extend(routesTmp)

	return mergeSubnets(routes)

def main():
	global proxies
	options = parseArguments()

	if not options.autonomousSystems:
		print tipMsg
		syslog.syslog(tipMsg)
		return

	# database source(s) (RIPE, RADB, etc)
	dbSource = options.db

	# proxies
	proxies = parseProxies(options.proxy, proxy)
	if useProxy and not proxies:
		print tipMsgProxy
		syslog.syslog(tipMsgProxy)
		return

	autonomousSystems = []
	asTmp = options.autonomousSystems.split(',')
	for system in asTmp:
		system = system.strip()
		if not system:
			continue
		if not system.lower().startswith('as'):
			system = 'AS' + system.strip()
		autonomousSystems.append(system)

	if not autonomousSystems:
		print tipMsg
		return

	result = getRoutesByAutonomousSystems(autonomousSystems, dbSource, proxies)
	print '\n'.join(result)

if __name__ == "__main__":
	main()



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
