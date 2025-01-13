# extenti/n of bro-1.5.3 landmine and bro-2.x darknet.bro

module Scan;

@load base/protocols/conn
#@load site-subnets.bro

export {
	global activate_LandMine = F &redef;

	const landmine_thresh_trigger = 5 &redef;
	const landmine_address: set[addr] &redef;

	redef enum Notice::Type += {
		LandMine, # source touched a landmine destination
		LandMineSummary, # aggregate of landmine scanner
	};

	global landmine_scan_summary: function(t: table[addr] of set[addr], orig: addr)
	    : interval;

	global landmine_distinct_peers: table[addr] of set[addr] &read_expire=1 day
	    &expire_func=landmine_scan_summary &redef;

	#	Expire functions that trigger summaries.
	global c_landmine_scan_summary: function(t: table[addr] of opaque of
	    cardinality, orig: addr): interval;

	global c_landmine_distinct_peers: table[addr] of opaque of cardinality
	    &default=function(n: any): opaque of cardinality {
		return hll_cardinality_init(0.1, 0.99);
	} &read_expire=1 days &expire_func=c_landmine_scan_summary;

	global landmine_ignore_ports: set[port] = {
		53/tcp,
		53/udp
	} &redef;

	# atleast these many subnets in the active subnets table
	const MIN_SUBNET_CHECK = 1;

	global check_LandMine: function(cid: conn_id, established: bool,
	    reversed: bool): bool;
	global filterate_LandMineScan: function(c: connection, darknet: bool): string;

	const allow_icmp_landmine_check: bool = F &redef;
	global ignore_landmine_ports: set[port] = { } &redef;
}

function landmine_scan_summary(t: table[addr] of set[addr], orig: addr)
    : interval
{
	#log_reporter(fmt("landmine_scan_summary: %s", |t[orig]|), 0);
	return 0 secs;
}

function check_LandMine(cid: conn_id, established: bool, reversed: bool): bool
{
	if ( gather_statistics )
		s_counters$c_land_checkscan += 1;

	local orig = cid$orig_h;
	local resp = cid$resp_h;
	local d_port = cid$resp_p;

	if ( orig in known_scanners && Scan::known_scanners[orig]$status ) {
		return F;
	}

	if ( resp in Site::local_nets && resp in Scan::subnet_table ) {
		log_reporter(fmt("PROBLEM - IP in site_subnet_table: %s", cid), 5);
		return F;
	}

	if ( [orig] !in landmine_distinct_peers )
		landmine_distinct_peers[orig] = set();

	if ( [resp] !in landmine_distinct_peers[orig] ) {
		add landmine_distinct_peers[orig][resp];

		if ( |landmine_distinct_peers[orig]| >= landmine_thresh_trigger ) {
			local iplist = "";

			for ( ip in landmine_distinct_peers[orig] ) {
				iplist += fmt(" %s", ip);
			}

			local msg = fmt("landmine address trigger %s [%s] %s", orig, d_port, iplist);
			NOTICE([$note=LandMine, $src=orig, $p=d_port, $id=cid, $msg=msg]);
			return T;
		}
	}

	#	if ([orig] !in c_landmine_distinct_peers)
	#	{
	#		local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99);
	#                c_landmine_distinct_peers[orig]=cp ;
	#	}
	#	hll_cardinality_add(c_landmine_distinct_peers[orig], resp);
	#
#	# local result = check_landmine_scan(orig, d_port, resp) ;
	#
#	local d_val = double_to_count(hll_cardinality_estimate(c_landmine_distinct_peers[orig])) ;
	#
#	if (d_val  >= landmine_thresh_trigger)
	#	{
	#		local msg=fmt ("Landmine hit by %s", orig);
	#		NOTICE([$note=LandMine, $src=orig, $src_peer=get_local_event_peer(), $msg=msg]);
	#		log_reporter (fmt ("NOTICE: FOUND LandMine : %s, %s", orig, network_time()),0);
	#		return T ;
	#	}

	return F;
}

function filterate_LandMineScan(c: connection, darknet: bool): string
{
	if ( gather_statistics )
		s_counters$c_land_filterate += 1;

	local orig = c$id$orig_h;
	local resp = c$id$resp_h;

	local orig_p = c$id$orig_p;
	local resp_p = c$id$resp_p;

	# check if src is local_nets, ignore for the time-being
	if ( orig in Site::local_nets )
		return "";

	# check if really Darknet IP or not
	if ( resp in Site::local_nets && resp in Scan::subnet_table )
		return "";

	# just in case
	if ( ! darknet )
		return "";

	# prevent manager to keep firing events if already a scanner
	if ( orig in Scan::known_scanners && Scan::known_scanners[orig]$status ) {
		#local rmsg = fmt ("landmine: known_scanner T: for %s, %s, %s", orig, resp_p, resp);
		#log_reporter(rmsg, 0);
		return "";
	}

	if ( /\^h/ in c$history )
		return "";

	if ( allow_icmp_landmine_check ) {
		if ( get_port_transport_proto(c$id$resp_p) == icmp
		    && c$id$resp_p in ignore_landmine_ports )
			return "";
	} else if ( get_port_transport_proto(c$id$resp_p) == icmp )
		return "";

	# limitation - works good only for tcp|icmp with minimal false positive
	# for udp see  - udp-scan.bro
	# enabling udp LandMine - 2019-09-16 aashish
	#if (get_port_transport_proto(c$id$resp_p) != tcp )
	#	return "";

	if ( resp_p in Scan::landmine_ignore_ports )
		return "";

	# min membership check if subnets-txt file is loaded
	# TODO: raise an alarm or take corrective actions
	# right now made failsafe - atleast 1 subnet needed

	if ( |Scan::subnet_table| < MIN_SUBNET_CHECK ) {
		#local msg = fmt("Scan::subnet_table is %d size which is below threshold. Deactivating LandMine Check", |Scan::subnet_table|);
		#event reporter_info(network_time(), msg, peer_description);
		return "";
	}

	#	if (orig in distinct_backscatter_peers)
	#		if (orig_p in distinct_backscatter_peers[orig])
	#			if (|distinct_backscatter_peers[orig][orig_p]| < 2)
	#				return "" ;

	if ( Site::is_local_addr(resp) && resp !in Scan::subnet_table ) {
		#if ((is_failed(c) || is_reverse_failed(c) ) )
		return "L";
	}

	return "";
}
# TODO: for future - add liveNet identification for in case subnet or parts of subnet from darknet
# wakes up

#@if ( ! Cluster::is_enabled())
#event connection_state_remove(c: connection)
#{
#	filterate_LandMineScan(c, T);
#}
#@endif

#const TCP_INACTIVE = 0; #< Endpoint is still inactive.
#const TCP_SYN_SENT = 1; #< Endpoint has sent SYN.
#const TCP_SYN_ACK_SENT = 2;     #< Endpoint has sent SYN/ACK.
#const TCP_PARTIAL = 3;  #< Endpoint has sent data but no initial SYN.
#const TCP_ESTABLISHED = 4;      #< Endpoint has finished initial handshake regularly.
#const TCP_CLOSED = 5;   #< Endpoint has closed connection.
#const TCP_RESET = 6;    #< Endpoint has sent RST.

# UDP values for :bro:see:`endpoint` *state* field.
# todo:: these should go into an enum to make them autodoc'able.
#const UDP_INACTIVE = 0; #< Endpoint is still inactive.
#const UDP_ACTIVE = 1;   #< Endpoint has sent something.

# vern's original landline detector from 1.5.3 era
# if ( activate_landmine_check &&
#     n >= landmine_thresh_trigger &&
#     mask_addr(resp, 24) in landmine_address )
#       {
#       local msg2 = fmt("landmine address trigger %s%s ", orig, svc);
#       NOTICE([$note=LandMine, $src=orig,
#               $p=service, $msg=msg2]);
#       }
