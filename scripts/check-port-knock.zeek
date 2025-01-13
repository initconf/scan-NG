# module to build network profile for scan detection 
# this module builds the 'ground-truth' ie prepares the list 
# legit LBNL servers and ports based on incoming SF.
# premise: if external IP connecting to something not in this list
# is likely a scan if (1) incoming connections meet fanout criteria 

# basically, the script works like this: 
# src: knock .
# src: knock ..	
# src: knock ...
# bro: bye-bye !!! 

# todo: 
# a. need backscatter identification (same src port diff dst port for scanner
# b. address 80/tcp, 443/tcp, 861/tcp, 389/tcp (sticky config)  - knock_high_threshold_ports 
# c. GeoIP integration - different treatment to > 130 miles IP vs US IPs vs Non-US IPs
# d. False +ve suppression and statistics _

module Scan;

#redef exit_only_after_terminate=F;

export {
	global activate_KnockKnockPort = T &redef;

	redef enum Notice::Type += {
		KnockKnockPort, # source flagged as scanner by TRW algorithm
		KnockKnockSummary, # summary of scanning activities reported by TRW
		LikelyScanner,
		IgnoreLikelyScanner,
		KnockSummary,
	};

	# sensitive and sticky config ports

	global high_sensitivity_ports: port = 33000/tcp;

	global scanner_default_ports: set[port] &redef;

	global hot_ports: set[port] &redef;

	redef hot_ports += {
		23/tcp,
		80/tcp,
		443/tcp,
		1433/tcp,
		22/tcp,
		6379/tcp,
		445/tcp,
		0/tcp,
		4028/tcp,
		3/tcp,
		3389/tcp,
		3306/tcp,
		25/tcp,
		8080/tcp,
		9200/tcp,
		53/tcp,
		861/tcp,
		49152/tcp,
		11720/tcp,
		20547/tcp,
		2082/tcp,
		5060/tcp,
		9999/tcp,
		444/tcp,
		3392/tcp,
		3391/tcp,
		27017/tcp,
		4444/tcp,
		3128/tcp,
		4899/tcp,
		5900/tcp,
		8128/tcp,
		11211/tcp,
		1/tcp,
		8090/tcp,
		8888/tcp,
		21/tcp,
		2222/tcp,
		110/tcp,
		47808/tcp,
		554/tcp,
		3393/tcp,
		17/tcp,
		10001/tcp,
		1093/tcp,
		8081/tcp,
		81/tcp,
		8088/tcp,
		102/tcp,
		8123/tcp,
		13/tcp,
		3390/tcp,
		10022/tcp,
		3386/tcp,
		40876/tcp,
		40884/tcp,
		10/tcp,
		1080/tcp,
		1755/tcp,
		161/tcp,
		3388/tcp,
		3394/tcp,
		3395/tcp,
		9100/tcp,
		6881/tcp,
		5901/tcp,
		3385/tcp,
		3384/tcp,
		3387/tcp,
		873/tcp,
		139/tcp,
		9600/tcp,
		7777/tcp,
		84/tcp,
		91/tcp,
		82/tcp,
		6666/tcp,
		502/tcp,
		902/tcp,
		27015/tcp,
		53413/tcp,
		32764/tcp,
		44818/tcp,
		88/tcp,
		8000/tcp,
		5038/tcp,
		1604/tcp,
		137/tcp,
		8082/tcp,
		87/tcp,
		5904/tcp,
		85/tcp,
		86/tcp,
		8/tcp,
		843/tcp,
		389/tcp,
		5222/tcp,
		5902/tcp,
		993/tcp,
		49153/tcp
	};

	# scan candidate 
	global likely_port_scanner: table[addr, addr] of set[port] &read_expire=1 day; # &synchronized ; 

	#global c_likely_port_scanner: table[addr,port] of opaque of cardinality
	#        &default = function(n: any): opaque of cardinality { return hll_cardinality_init(0.1, 0.99); }
	#	&read_expire=1 day  ; 

	global HIGH_THRESHOLD_LIMIT = 30 &redef;
	global MED_THRESHOLD_LIMIT = 12 &redef;
	global LOW_THRESHOLD_LIMIT = 3 &redef;

	global COMMUTE_DISTANCE = 320 &redef;

	global check_knockknock_port: function(orig: addr, d_port: port, resp: addr): bool;
	global check_KnockKnockPort: function(cid: conn_id, established: bool,
	    reverse: bool): bool;
	global filterate_KnockKnockPort: function(c: connection, darknet: bool): string;

	global c_concurrent_scanners_per_port: table[port] of opaque of cardinality
	    &default=function(n: any): opaque of cardinality {
		return hll_cardinality_init(0.1, 0.99);
	} &read_expire=1 day;
}

function check_knockknock_port(orig: addr, d_port: port, resp: addr): bool
{
	local result = F;

	local high_threshold_flag = F;
	local medium_threshold_flag = F;
	local low_threshold_flag = F;

	# # # # # # # # # # #
	# code and heuristics of to determine if orig is inface a scanner

	# gather geoip distance
	local orig_loc = lookup_location(orig);
	local resp_loc = lookup_location(resp);

	local distance = 0.0;
	#distance = get_haversine_distance(orig, resp);

	# if driving distance, we raise the block threshold
	# 6 hours - covers tahoe and Yosemite from berkeley
	if ( distance < COMMUTE_DISTANCE ) {
		high_threshold_flag = F;
	}

	if ( d_port !in c_concurrent_scanners_per_port ) {
		local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99);
		c_concurrent_scanners_per_port[d_port] = cp;
	}

	hll_cardinality_add(c_concurrent_scanners_per_port[d_port], orig);

	local d_val = double_to_count(hll_cardinality_estimate(
	    c_concurrent_scanners_per_port[d_port]));

	# check if in knock_high_threshold_ports or rare port scan (too few concurrent scanners)
	# notch up threshold ot high  - likewise for medium thresholds

	if ( d_port > high_sensitivity_ports || d_val >= 10 ) {
		high_threshold_flag = T;
	} else if ( d_port in hot_ports || d_val >= 5 ) {
		low_threshold_flag = T;
	}

	if ( orig !in Scan::known_scanners ) {
		if ( |likely_port_scanner[orig, resp]| == HIGH_THRESHOLD_LIMIT
		    && high_threshold_flag ) {
			result = T;
		} else if ( |likely_port_scanner[orig, resp]| == MED_THRESHOLD_LIMIT
		    && medium_threshold_flag ) {
			result = T;
		} #else if (|likely_port_scanner[orig,resp]| >= LOW_THRESHOLD_LIMIT && !high_threshold_flag && !medium_threshold_flag)
		else if ( |likely_port_scanner[orig, resp]| >= LOW_THRESHOLD_LIMIT
		    && low_threshold_flag ) {
			result = T;
		}
	}

	if ( result ) {
		# make sure there is country code
		local cc = orig_loc?$country_code ? orig_loc$country_code : "";

		# build list of hosts touched

		local hosts_probed = "";
		for ( a in likely_port_scanner[orig, resp] )
			hosts_probed += fmt(" %s ", a);

		local _msg = fmt("%s scanned a total of %d ports on %s: (origin: %s distance: %.2f miles) on %s", orig,
		    |likely_port_scanner[orig, resp]|, resp, cc, distance,
		    hosts_probed);
		NOTICE([$note=KnockKnockPort, $src=orig, $msg=fmt("%s", _msg)]);
		log_reporter(fmt("check_knockknock_scan: %s, %s, %s, %s, %s - DETECTED", orig, d_port, resp,
		    network_time(), current_time()), 1);

	#Scan::add_to_known_scanners(orig, "KnockKnockPort"); 
	}
	# # # # # # # # # # #
	return result;
}

function check_KnockKnockPort(cid: conn_id, established: bool, reverse: bool): bool
{
	# already filterated connection 

	local orig = cid$orig_h;
	local resp = cid$resp_h;
	local d_port = cid$resp_p;

	#already identified as scanner no need to proceed further 
	if ( orig in Scan::known_scanners && Scan::known_scanners[orig]$status )
		return F;

	# only worry about TCP connections
	# we deal with udp and icmp scanners differently

	if ( get_port_transport_proto(cid$resp_p) != tcp )
		return F;

	if ( [orig, resp] !in likely_port_scanner ) {
		likely_port_scanner[orig, resp] = set();
	}

	if ( d_port !in likely_port_scanner[orig, resp] ) {
		add likely_port_scanner[orig, resp][d_port];
	}

	local result = check_knockknock_port(orig, d_port, resp);

	# TODO: this should go down further into check-scan-impl.bro code 
	if ( result ) {
		# Important want ot make sure we update the detect_ts to nearest time of occurence 
		#Scan::known_scanners[orig]$detect_ts = network_time(); 
		#log_reporter(fmt("knockknock port scanner detected at %s, %s on %s", orig, Scan::known_scanners[orig]$detect_ts, peer_description),0); 

		return T;
	}

	return F;
}

# clusterizations 

event udp_request(u: connection)
{ }

event udp_reply(u: connection)
{ }

event connection_state_remove(c: connection)
{
	local darknet = F;

	if ( /PortKnock/ in filterate_KnockKnockPort(c, F) ) {
		if ( check_KnockKnockPort(c$id, F, F) ) {
			log_reporter(fmt("connection_state_remove: w_m_update_scanner: %s",
			    known_scanners[c$id$orig_h]), 0);
			event Scan::w_m_update_scanner(known_scanners[c$id$orig_h]);
		}
	}
}

function filterate_KnockKnockPort(c: connection, darknet: bool): string
{
	if ( ! activate_KnockKnockPort )
		return "";

	local orig = c$id$orig_h;
	local resp = c$id$resp_h;
	local d_port = c$id$resp_p;
	local s_port = c$id$orig_p;

	# internal host scanning handled seperately 
	if ( Site::is_local_addr(c$id$orig_h) )
		return "";

	#local darknet = Scan::is_darknet(c$id$resp_h); 

	# only worry about TCP connections 	
	# we deal with udp and icmp scanners differently 
	if ( get_port_transport_proto(c$id$resp_p) != tcp )
		return "";

	# a) full established conns not interesting 
	if ( c$resp$state == TCP_ESTABLISHED ) {
		return "";
	}

	# b) full established conns not interesting 
	if ( c?$conn && c$conn?$conn_state ) {
		if ( /SF/ in c$conn$conn_state ) {
			return "";
		}

		local state = c$conn$conn_state;
		local resp_bytes = c$resp$size;

		# mid stream traffic - ignore  
		if ( state == "OTH" && resp_bytes > 0 ) {
			return "";
		}
	}

	# if ever a SF a LBL host on this port - ignore the orig completely 
	if ( resp in Site::host_profiles && d_port in Site::host_profiles[resp] )
		return "";

	# don't need to process known_scanners again 	
	if ( orig in Scan::known_scanners && Scan::known_scanners[orig]$status ) {
		#	log_reporter(fmt("check_KnockKnockPort: orig in known_scanner"),0); 
		return "";
	}

	# finally a scan candidate 	
	return "PortKnock";
#add_to_knockknock_cache(orig, d_port, resp); 
}
