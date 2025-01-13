module Scan;

export {
	global activate_AddressScan = T &redef;

	redef enum Notice::Type += {
		AddressScan, # the source has scanned a number of addrs
		ScanSummary, # summary of scanning activity
		ShutdownThresh, # source reached shut_down_thresh
	};

	# Which services should be analyzed when detecting scanning
	# (not consulted if analyze_all_services is set).
	const analyze_services: set[port] &redef;
	const analyze_all_services = T &redef;

	# Report a scan of peers at each of these points.
	const report_peer_scan: vector of count = {
		20,
		30,
		50,
		100,
		1000,
		10000,
		50000,
		100000,
		250000,
		500000,
		1000000,
	} &redef;

	const report_outbound_peer_scan: vector of count = {
		20,
		30,
		50,
		100,
		1000,
		10000,
	} &redef;

	global thresh_check: function(v: vector of count, idx: table[addr] of count,
	    orig: addr, n: count): bool;

	global rps_idx: table[addr] of count &default=1 &read_expire=1 days &redef;
	global rops_idx: table[addr] of count &default=1 &read_expire=1 days &redef;

	# Expire functions that trigger summaries.
	global scan_sum: function(t: table[addr] of set[addr], orig: addr): interval;

	# scan storage containers
	global distinct_peers: table[addr] of set[addr] &read_expire=1 days
	    &expire_func=scan_sum &redef;

	global c_distinct_peers: table[addr] of opaque of cardinality
	    &default=function(n: any): opaque of cardinality {
		return hll_cardinality_init(0.1, 0.99);
	} &read_expire=1 day; # &expire_func=scan_sum &redef;

	const scan_summary_trigger = 25 &redef;

	global shut_down_thresh_reached: table[addr] of bool &default=F;

	# Raise ShutdownThresh after this many failed attempts
	const shut_down_thresh = 100 &redef;

	# addressscan
	# Ignore address scanners for further scan detection after
	# scanning this many hosts.
	# 0 disables.
	const ignore_scanners_threshold = 0 &redef;

# changed this to use hyperloglog functions
# global distinct_peers: table[addr] of set[addr]
#        &read_expire = 1 day &expire_func=scan_sum &redef;

# global distinct_peers: table[addr] of opaque of cardinality
#       &default = function(n: any): opaque of cardinality { return hll_cardinality_init(0.1, 0.99); }
#        &read_expire = 1 day &expire_func=scan_sum &redef;
}

# To recognize whether a certain threshhold vector (e.g. report_peer_scans)
# has been transgressed, a global variable containing the next vector index
# (idx) must be incremented.  This cumbersome mechanism is necessary because
# values naturally don't increment by one (e.g. replayed table merges).
function thresh_check(v: vector of count, idx: table[addr] of count, orig: addr,
    n: count): bool
{
	if ( ignore_scanners_threshold > 0 && n > ignore_scanners_threshold ) {
		#ignore_addr(orig);
		return F;
	}

	if ( idx[orig] <= |v| && n >= v[idx[orig]] ) {
		++idx[orig];
		return T;
	} else
		return F;
}

function scan_sum(t: table[addr] of set[addr], orig: addr): interval
{
	# log_reporter(fmt("scan_sum invoked for %s", t[orig]),0);

	local num_distinct_peers = orig in t ? |t[orig]| : 0;

	if ( num_distinct_peers >= scan_summary_trigger ) {
		NOTICE([
		    $note=ScanSummary,
		    $src=orig,
		    $n=num_distinct_peers,
		    $msg=fmt("%s scanned a total of %d hosts", orig, num_distinct_peers)]);
	}
	return 0 secs;
}

function check_address_scan_thresholds(orig: addr, resp: addr, outbound: bool,
    n: count): bool
{
	#A	 if (gather_statistics)
	#                s_counters$c_addressscan_core+= 1  ;

	local address_scan = F;

	if ( outbound && # inside host scanning out?
	thresh_check(report_outbound_peer_scan, rops_idx, orig, n) )
		address_scan = T;

	if ( ! outbound && thresh_check(report_peer_scan, rps_idx, orig, n) )
		address_scan = T;

	return address_scan;
}

# filterate_AddresssScan runs on workers and does all the pre-filtering for
# potential scan candidates

function filterate_AddressScan(c: connection, established: bool, reverse: bool): string
{


	# lets handle established connections differently for now
	# since we have many corner caseses around it
	if ( established)
		return "";

	#A	 if (gather_statistics)
	#             s_counters$c_addressscan_filterate += 1  ;

	# only deal with tcp
	local trans = get_port_transport_proto(c$id$resp_p);

	if ( trans != tcp )
		return "";

	if (!( c$history == "S" || c$history == "SW" ||
		 c$history == "Sr" || c$history == "SWr"))
		return "" ;

	local id = c$id;

	local service = "ftp-data" in c$service ? 20/tcp : ( reverse ? id$orig_p :
	    id$resp_p );
	local rev_service = reverse ? id$resp_p : id$orig_p;
	local orig = reverse ? id$resp_h : id$orig_h;
	local resp = reverse ? id$orig_h : id$resp_h;
	local outbound = Site::is_local_addr(orig);
	local orig_p = c$id$orig_p;

	# unless a known_scanner consider everything a scanner
	if ( orig in Scan::known_scanners && Scan::known_scanners[orig]$status )
		return "";

	# we do not watch for local address
	# we will do internal scan-detection seperately
	# using all-check

	if ( Site::is_local_addr(orig) )
		return "";

	# optional filters to reduce load on manager
	# we ignore all darknet connections since LandMine will take care of it
	# ( check if Scan::activate_LandMine = T ; )

	# TODO
	#if (Scan::activate_LandMine && is_darknet(resp))
	if ( is_darknet(resp) )
		return "";

	# we can ignore all the non-existing services since knockknock can take
	# care of it

	#if (Scan::activate_KnockKnock && resp in Site::host_profiles)
	#	return "" ;

	# issue is how to identify legit connections and not send those
	if ( established )
		return "";

	# The following works better than using get_conn_transport_proto()
	# because c might not correspond to an active connection (which
	# causes the function to fail).
	# aashish UDP
	if ( suppress_UDP_scan_checks && service >= 0/udp && service <= 65535/udp )
		return "";

	if ( service in skip_services && ! outbound )
		return "";

	if ( outbound && service in skip_outbound_services )
		return "";

	if ( orig in skip_scan_sources )
		return "";

	if ( orig in skip_scan_nets )
		return "";

	# Don't include well known server/ports for scanning purposes.
	if ( ! outbound && [resp, service] in skip_dest_server_ports )
		return "";

	if ( orig in ignored_scanners )
		return "";

	return "A";
}

# runs on manager to consolidate all connections which workers see
function check_AddressScan(cid: conn_id, established: bool, reverse: bool): bool
{
	#A	 if (gather_statistics)
	#               s_counters$c_addressscan_checkscan += 1  ;

	local trans = get_port_transport_proto(cid$orig_p);

	if ( trans != tcp )
		return F;

	local id = cid;
	local result = F;

	local service = reverse ? id$orig_p : id$resp_p;
	local rev_service = reverse ? id$resp_p : id$orig_p;
	local orig = reverse ? id$resp_h : id$orig_h;
	local resp = reverse ? id$orig_h : id$resp_h;
	local outbound = Site::is_local_addr(orig);
	local orig_p = cid$orig_p;

	# TODO
	#	if (orig in c_distinct_backscatter_peers)
	#		if (orig_p in c_distinct_backscatter_peers[orig])
	#		{
	#if (|distinct_backscatter_peers[orig][orig_p]| < 2)
	#			local bsc = double_to_count(hll_cardinality_estimate(c_distinct_backscatter_peers[orig])) ;
	#			if ( bsc < 2)
	#				result = F ;
	#		}
	#
	# log_reporter(fmt("add_to_addressscan_cache: check_AddressScan: %s", c$id),0);

	local resp_count = double_to_count(hll_cardinality_estimate(
	    c_distinct_peers[orig]));

	local n = 0;

	if ( ( ! established ) && # not established, service not expressly allowed
	# not known peer set
	( orig !in distinct_peers || resp !in distinct_peers[orig] )
	    || ( orig !in c_distinct_peers || resp_count != 0.0 )
	    && # want to consider service for scan detection
	( analyze_all_services || service in analyze_services ) ) {
		if ( enable_big_tables ) {
			if ( orig !in distinct_peers )
				distinct_peers[orig] = set();

			if ( resp !in distinct_peers[orig] )
				add distinct_peers[orig][resp];

			n = |distinct_peers[orig]|;
		} else {
			if ( orig !in c_distinct_peers ) {
				local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99);
				c_distinct_peers[orig] = cp;
			}

			hll_cardinality_add(c_distinct_peers[orig], resp);

			n = double_to_count(hll_cardinality_estimate(c_distinct_peers[orig]));
		}

		local address_scan_result = check_address_scan_thresholds(orig, resp,
		    outbound, n);

		if ( address_scan_result ) {
			# we block likely_server_port scanners at higher threshold than other ports)
			if ( ( service in likely_server_ports && n > 99 )
			    || ( service !in likely_server_ports ) ) {
				NOTICE([
				    $note=AddressScan,
				    $src=orig,
				    $id=cid,
				    $p=service,
				    $n=n,
				    $msg=fmt("%s has scanned %d hosts (%s)", orig, n, service)]);

				#log_reporter (fmt ("NOTICE: FOUND AddressScan: %s", orig),0);

				result = T;
			}
		}
	}

	# Check for threshold if not outbound.
	if ( ! shut_down_thresh_reached[orig]
	    && n >= shut_down_thresh
	    && ! outbound
	    && orig !in Site::neighbor_nets ) {
		shut_down_thresh_reached[orig] = T;
		local msg = fmt("shutdown threshold reached for %s", orig);
		NOTICE([$note=ShutdownThresh, $src=orig, $p=service, $msg=msg]);

		result = T;

		Scan::add_to_known_scanners(orig, "ShutdownThresh");
		Scan::known_scanners[orig]$detect_ts = network_time();
	}

	# backscater check - we don't want to send events to manager for addressscan if
	# this is a backscatter traffic
	# which is generally characterized by |s_port| == 1

	return result;
}
#
#        if ( orig in Scan::known_scanners)
#		if (Scan::known_scanners[orig]$status)
#		        { return; }
#
#        if ([orig] !in distinct_peers)
#                distinct_peers[orig]=set() ;
#
#        add distinct_peers[orig][resp];
#
#	local n = |distinct_peers[orig]|;
#
#        local result = check_address_scan_thresholds(orig, resp, outbound, n) ;
#
#	if (result)
#	{
#		NOTICE([$note=AddressScan,
#				$src=orig, $p=service, $n=n,
#				$msg=fmt("%s has scanned %d hosts (%s)", orig, n, service)]);
#	}

# events for scan detections

# event connection_established(c: connection)
#        {
#        local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#            Scan::check_AddressScan(c$id, T, is_reverse_scan);
#
#         local trans = get_port_transport_proto(c$id$orig_p);
#         #if ( trans == tcp && ! is_reverse_scan && TRW::use_TRW_algorithm )
#         #      TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event partial_connection(c: connection)
#        {
#        Scan::check_AddressScan(c$id, T, F);
#        }
#
#event connection_attempt(c: connection)
#        {
#    local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#        Scan::check_AddressScan(c$id, F, is_reverse_scan);
#
#         local trans = get_port_transport_proto(c$id$orig_p);
#         #if ( trans == tcp && TRW::use_TRW_algorithm )
#         #      TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event connection_half_finished(c: connection)
#        {
#        # Half connections never were "established", so do scan-checking here.
#        Scan::check_AddressScan(c$id, F, F);
#        }
#
#event connection_rejected(c: connection)
#        {
#        local is_reverse_scan = (c$orig$state == TCP_RESET && c$id$resp_p !in likely_server_ports);
#
#        Scan::check_AddressScan(c$id, F, is_reverse_scan);
#
#         #local trans = get_port_transport_proto(c$id$orig_p);
#         #if ( trans == tcp && TRW::use_TRW_algorithm )
#         #       TRW::check_TRW_scan(c, conn_state(c, trans), is_reverse_scan);
#        }
#
#event connection_reset(c: connection)
#        {
#        if ( c$orig$state == TCP_INACTIVE || c$resp$state == TCP_INACTIVE )
#        {
#        local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#                 # We never heard from one side - that looks like a scan.
#                Scan::check_AddressScan(c$id, c$orig$size + c$resp$size > 0, is_reverse_scan);
#        }
#        }
#
#event connection_pending(c: connection)
#        {
#        if ( c$orig$state == TCP_PARTIAL && c$resp$state == TCP_INACTIVE )
#                Scan::check_AddressScan(c$id, F, F);
#        }
#
#
