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
	global activate_KnockKnockScan = F &redef;

	redef enum Notice::Type += {
		KnockKnockScan,
		KnockKnockSummary,
		LikelyScanner,
		IgnoreLikelyScanner,
		KnockSummary,
	};

	# sensitive and sticky config ports
	option knock_high_threshold_ports: set[port] = {
		861/tcp,
		80/tcp,
		#443/tcp,
		#8443/tcp,
		8080/tcp
	} &redef;

	option knock_medium_threshold_ports: set[port] = {
		17500/tcp, # dropbox-lan-sync
		135/tcp,
		139/tcp,
		445/tcp,
		0/tcp,
		389/tcp,
		88/tcp,
		3268/tcp,
		52311/tcp,
	} &redef;

	#redef knock_high_threshold_ports += { 113/tcp, 636/tcp, 135/tcp, 139/tcp, 17500/tcp, 18457/tcp,
	#                                3268/tcp, 3389/tcp, 3832/tcp, 389/tcp,
	#                                4242/tcp, 443/tcp, 445/tcp, 52311/tcp, 5900/tcp,
	#                                60244/tcp, 60697/tcp, 80/tcp, 8080/tcp, 7000/tcp, 8192/tcp,
	#                                8194/tcp, 8443/tcp, 88/tcp, 9001/tcp,
	#                                };

	# scan candidate

	global expire_likely_scanner: function(t: table[addr, port] of set[addr], a: addr, p: port)
	    : interval;
	global likely_scanner: table[addr, port] of set[addr] = table() &read_expire=1 day; # &synchronized ;

	global c_likely_scanner: table[addr, port] of opaque of cardinality
	    &default=function(a: addr, p: port): opaque of cardinality {
		return hll_cardinality_init(0.1, 0.99);
	} &read_expire=1 day;

	global HIGH_THRESHOLD_LIMIT = 12 &redef;
	global MED_THRESHOLD_LIMIT = 5 &redef;
	global LOW_THRESHOLD_LIMIT = 3 &redef;

	global COMMUTE_DISTANCE = 320 &redef;

	# automated_exceptions using input-framework
	global ipportexclude_file = "/YURT/feeds/BRO-feeds/knockknock.exceptions" &redef;

	type ipportexclude_Idx: record {
		exclude_ip: addr;
		exclude_port: port &type_column="t";
	};

	type ipportexclude_Val: record {
		exclude_ip: addr;
		exclude_port: port &type_column="t";
		comment: string &optional;
	};

	global ipportexclude: table[addr, port] of ipportexclude_Val = table() &redef; # &synchronized ;
	#global concurrent_scanners_per_port: table[port] of set[addr] &write_expire=6 hrs ; # &synchronized ;

	# clusterization helper events
	global m_w_knockscan_add: event(orig: addr, d_port: port, resp: addr);
	global w_m_knockscan_new: event(orig: addr, d_port: port, resp: addr);
	global add_to_knockknock_cache: function(orig: addr, d_port: port, resp: addr);

	global check_knockknock_scan: function(orig: addr, d_port: port, resp: addr): bool;
	global check_KnockKnockScan: function(cid: conn_id, established: bool,
	    reverse: bool): bool;

	global filterate_KnockKnockScan: function(c: connection, darknet: bool): string;
}

function expire_likely_scanner(t: table[addr, port] of set[addr], a: addr, p: port)
    : interval
{
	log_reporter(fmt("expire_likely_scanner: %s, %s, %s", a, p, t[a, p]), 25);
	return 0 secs;
}

function check_knockknock_scan(orig: addr, d_port: port, resp: addr): bool
{
	if ( gather_statistics )
		s_counters$c_knock_core += 1;

	local result = F;

	local high_threshold_flag = F;
	local medium_threshold_flag = F;
	local usual_threshold_flag = F;
	local ultra_low_threshold_flag = F;

	# code and heuristics of to determine if orig is inface a scanner

	# gather geoip distance
	local orig_loc = lookup_location(orig);
	local resp_loc = lookup_location(resp);

	local distance = 0.0;
	distance = haversine_distance_ip(orig, resp);

	#print fmt ("%s, %s, %s", orig, d_port, resp);

	# We want to check for distributed scanners
	# basically flag scanners which remain below
	# block thresholds (esp happens in ipv6 world
	# we apply new heuristics: if a likely_scanner
	# is from a hotsubnet, we call it a scanner
	# this is sort of landmine version of knockknock


	local nnote: Notice::Type = KnockKnockScan;

	if (isHotSubnet(orig))
	{
		#ultra_low_threshold_flag = T;
		#nnote = SubnetKnock;
		local a = 0 ;
	}

	# if driving distance, we raise the block threshold
	# 6 hours - covers tahoe and Yosemite from berkeley
	if ( distance < COMMUTE_DISTANCE ) {
		high_threshold_flag = T;
	}

	#if (d_port !in concurrent_scanners_per_port)
	#{
	#	concurrent_scanners_per_port[d_port]=set();
	#}

	# stop populating the table if > 6 simultenious scanners
	# are probing on the same port. IN this case we
	# reduce the threshold to 3 faolures to block
	#if (|concurrent_scanners_per_port[d_port]| <=5)
	#{
	#	add concurrent_scanners_per_port[d_port][orig] ;
	#}

	local flux_density = check_port_flux_density(d_port, orig);

	# check if in knock_high_threshold_ports or rare port scan (too few concurrent scanners)
	# notch up threshold ot high  - likewise for medium thresholds

	#if (! high_threshold_flag )
	#{
	#       if (d_port in knock_high_threshold_ports  || |concurrent_scanners_per_port[d_port]| <=2)
	#       {       high_threshold_flag = T ; }
	#       else if (d_port in knock_medium_threshold_ports  || |concurrent_scanners_per_port[d_port]| <=5)
	#       {       medium_threshold_flag = T ;  }
	#}

	if ( ! high_threshold_flag ) {
		if ( d_port in knock_high_threshold_ports || flux_density <= 2 ) {
			high_threshold_flag = T;
		} else if ( d_port in knock_medium_threshold_ports || flux_density <= 5 ) {
			medium_threshold_flag = T;
		}
	}

	local d_val = 0;

	if ( orig !in Scan::known_scanners ) {
		if ( enable_big_tables ) {
			d_val = |likely_scanner[orig, d_port]|;
		} else {
			d_val = double_to_count(hll_cardinality_estimate(c_likely_scanner[orig,
			    d_port]));
		}

		if ( d_val == HIGH_THRESHOLD_LIMIT && high_threshold_flag ) {
			result = T;
		} else if ( d_val == MED_THRESHOLD_LIMIT && medium_threshold_flag ) {
			result = T;
		} else if ( d_val >= LOW_THRESHOLD_LIMIT
		    && ! high_threshold_flag
		    && ! medium_threshold_flag ) {
			result = T;
		}
	}

	if (ultra_low_threshold_flag)
		result = T;

	if ( result ) {
		# make sure there is country code
		local cc = orig_loc?$country_code ? orig_loc$country_code : "";

		#local _msg = fmt("%s scanned a total of %d hosts: [%s] (port-flux-density: %s) (origin: %s distance: %.2f miles)", orig, d_val,d_port, |concurrent_scanners_per_port[d_port]|, cc, distance);
		local _msg = fmt("%s scanned a total of %d hosts: [%s] (port-flux-density: %s) (origin: %s distance: %.2f miles)", orig, d_val, d_port,
		    flux_density, cc, distance);

		#$ts=current_time(),
		NOTICE([$note=nnote, $src=orig, $p=d_port, $msg=fmt("%s", _msg)]);

	}
	#log_reporter (fmt ("NOTICE: FOUND %s: %s on %s", nnote, orig, Cluster::node),0);
	return result;
}

#check_knockknock_scan: 222.85.138.75, 3128/tcp, 131.243.192.47, 1463019177.63643, 1463019216.164206 - DETECTED
#1463019177.636430 error in ./.././check-knock.bro, line 199: value used but not set (Scan::add_to_known_scanners)
#1463019177.636430 error in ./.././check-knock.bro, line 250: no such index (Scan::known_scanners[Scan::orig])
#1463019177.636430 error in ./.././check-knock.bro, line 251: no such index (Scan::known_scanners[Scan::orig])

function check_KnockKnockScan(cid: conn_id, established: bool, reverse: bool): bool
{
	local result = F;

	if ( gather_statistics )
		s_counters$c_knock_checkscan += 1;

	# already filterated connection
	local orig = cid$orig_h;
	local resp = cid$resp_h;
	local d_port = cid$resp_p;

	#already identified as scanner no need to proceed further
	if ( orig in Scan::known_scanners && Scan::known_scanners[orig]$status )
		return F;

	# only worry about TCP connections
	# we deal with udp and icmp scanners differently

	# aashish UDP
	if ( get_port_transport_proto(cid$resp_p) != tcp )
		return F;

	# memory optimizations
	if ( enable_big_tables ) {
		if ( [orig, d_port] !in likely_scanner ) {
			likely_scanner[orig, d_port] = set();
		}

		if ( resp !in likely_scanner[orig, d_port] ) {
			add likely_scanner[orig, d_port][resp];
		}
	} else {
		if ( [orig, d_port] !in c_likely_scanner ) {
			local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99);
			c_likely_scanner[orig, d_port] = cp;
		}

		hll_cardinality_add(c_likely_scanner[orig, d_port], resp);
	}

	result = check_knockknock_scan(orig, d_port, resp);

	return result;
}

@if ( ! Cluster::is_enabled() )
event connection_state_remove(c: connection)
{
	local darknet = F;
#	check_KnockKnockScan(c$id, F, F) ;
}
@endif

function filterate_KnockKnockScan(c: connection, darknet: bool): string
{
	if ( gather_statistics )
		s_counters$c_knock_filterate += 1;

	if ( ! activate_KnockKnockScan )
		return "";

	local orig = c$id$orig_h;
	local resp = c$id$resp_h;
	local d_port = c$id$resp_p;
	local s_port = c$id$orig_p;

	# internal host scanning handled seperately
	if ( Site::is_local_addr(c$id$orig_h) )
		return "";

	if ( /\^/ in c$history)
		return "" ;

	#local darknet = Scan::is_darknet(c$id$resp_h);

	if ( ! darknet ) {
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
	}

	# ignore traffic to host/port  this is primarily whitelisting
	# maintained in ipportexclude_file for sticky config firewalled hosts
	if ( [resp, d_port] in ipportexclude ) {
		return "";
	}

	# if ever a SF a LBL host on this port - ignore the orig completely
	if ( resp in Site::host_profiles && d_port in Site::host_profiles[resp] )
		return "";

	# don't need to process known_scanners again
	if ( orig in Scan::known_scanners && Scan::known_scanners[orig]$status ) {
		log_reporter(fmt("check_KnockKnockScan: orig in known_scanner"), 0);
		return "";
	}

	# finally a scan candidate
	return "K";
#add_to_knockknock_cache(orig, d_port, resp);
}

event zeek_init()
{
	Input::add_table([
	    $source=ipportexclude_file,
	    $name="ipportexclude",
	    $idx=ipportexclude_Idx,
	    $val=ipportexclude_Val,
	    $destination=ipportexclude,
	    $mode=Input::REREAD]);
}
