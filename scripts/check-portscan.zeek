module Scan;

export {
	const activate_PortScan = T &redef;

	redef enum Notice::Type += {
		PortScan, # the source has scanned a number of ports
		PortScanSummary, # summary of distinct ports per scanner
	};

	# If true, we suppress scan-checking (we still do account-tried
	# accounting).  This is provided because scan-checking can consume
	# a lot of memory.
	const suppress_scan_checks = F &redef;

	global port_summary: function(t: table[addr] of set[port], orig: addr)
	    : interval;

	global distinct_ports: table[addr] of set[port] &read_expire=1 days
	    &expire_func=port_summary &redef;

	const port_summary_trigger = 20 &redef;

	global rpts_idx: table[addr, addr] of count &default=1 &read_expire=1 days &redef;

	# Indexed by scanner address, yields a table with scanned hosts
	# (and ports).
	global scan_triples: table[addr] of table[addr] of set[port];

	# Report a scan of ports at each of these points.
	const report_port_scan: vector of count = {
		50,
		250,
		1000,
		5000,
		10000,
		25000,
		65000,
	} &redef;

	# Once a source has scanned this many different ports (to however many
	# different remote hosts), start tracking its per-destination access.
	const possible_port_scan_thresh = 20 &redef;

	global remove_possible_source: function(s: set[addr], idx: addr): interval;
	global possible_scan_sources: set[addr] &expire_func=remove_possible_source
	    &read_expire=1 days;

	global filterate_PortScan: function(c: connection, established: bool,
	    reverse: bool): string;
	global check_PortScan: function(c: connection, established: bool,
	    reverse: bool);

	global thresh_check_2: function(v: vector of count, idx: table[addr, addr] of count,
	    orig: addr, resp: addr, n: count): bool;
}

# Same as thresh_check, except the index has a different type signature.
function thresh_check_2(v: vector of count, idx: table[addr, addr] of count,
    orig: addr, resp: addr, n: count): bool
{
	if ( ignore_scanners_threshold > 0 && n > ignore_scanners_threshold ) {
		ignore_addr(orig);
		return F;
	}

	if ( idx[orig, resp] <= |v| && n >= v[idx[orig, resp]] ) {
		++idx[orig, resp];
		return T;
	} else
		return F;
}

@if ( Cluster::is_enabled() )
export {
	global Scan::m_w_portscan_update_known_scanners: event(orig: addr);
	global Scan::w_m_portscan_new: event(orig: addr, d_port: port, resp: addr,
	    outbound: bool);
	global Scan::add_to_portscan_cache: function(orig: addr, d_port: port,
	    resp: addr);
}
@endif

#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /Scan::m_w_portscan_update_known_scanners/;
#redef Cluster::worker2manager_events += /Scan::w_m_portscan_new/;
#@endif

function port_summary(t: table[addr] of set[port], orig: addr): interval
{
	local num_distinct_ports = orig in t ? |t[orig]| : 0;

	if ( num_distinct_ports >= port_summary_trigger )
		NOTICE([
		    $note=PortScanSummary,
		    $src=orig,
		    $n=num_distinct_ports,
		    $msg=fmt("%s scanned a total of %d ports", orig, num_distinct_ports)]);

	return 0 secs;
}

function check_portscan_thresh(orig: addr, service: port, resp: addr): bool
{
	if ( orig !in scan_triples )
		scan_triples[orig] = table();

	if ( resp !in scan_triples[orig] )
		scan_triples[orig][resp] = set();

	if ( service !in scan_triples[orig][resp] ) {
		add scan_triples[orig][resp][service];

		if ( thresh_check_2(report_port_scan, rpts_idx, orig, resp,
		    |scan_triples[orig][resp]|) ) {
			local m = |scan_triples[orig][resp]|;
			NOTICE([
			    $note=PortScan,
			    $n=m,
			    $src=orig,
			    $p=service,
			    $msg=fmt("%s has scanned %d ports of %s", orig, m, resp)]);
			return T;
		}
	}

	return F;
}

function filterate_PortScan(c: connection, established: bool, reverse: bool): string
{
	if ( ! activate_PortScan )
		return "";

	return "P";
}

function check_PortScan(c: connection, established: bool, reverse: bool)
{
	#if ( suppress_scan_checks )
	#        return ;

	if ( ! established ) {
		# Don't consider established connections for port scanning,
		# it's too easy to be mislead by FTP-like applications that
		# legitimately gobble their way through the port space.
		return;

		local id = c$id;

		local service = "ftp-data" in c$service ? 20/tcp : ( reverse ? id$orig_p :
		    id$resp_p );
		local rev_service = reverse ? id$resp_p : id$orig_p;
		local orig = reverse ? id$resp_h : id$orig_h;
		local resp = reverse ? id$orig_h : id$resp_h;
		local outbound = Site::is_local_addr(orig);

		#if (orig in Scan::known_scanners)
		if ( Scan::known_scanners[orig]$status )
			return;

		# Coarse search for port-scanning candidates: those that have made
		# connections (attempts) to possible_port_scan_thresh or more
		# distinct ports.
		if ( orig !in distinct_ports || service !in distinct_ports[orig] ) {
			if ( orig !in distinct_ports )
				distinct_ports[orig] = set();

			if ( service !in distinct_ports[orig] )
				add distinct_ports[orig][service];

			if ( |distinct_ports[orig]| >= possible_port_scan_thresh
			    && orig !in scan_triples ) {
				scan_triples[orig] = table();
				add possible_scan_sources[orig];
			}
		}

		# Check for low ports.
		#	if ( activate_LowPortTrolling && ! outbound && service < 1024/tcp &&
		#	     service !in troll_skip_service )
		#	{
		#		local troll_result = check_lowporttrolling(orig, service, resp); 
		local troll_result = "";
		#	}

		# For sources that have been identified as possible scan sources,
		# keep track of per-host scanning.
		if ( orig in possible_scan_sources ) {
			local thresh_result = check_portscan_thresh(orig, service, resp);
		}

@if ( Cluster::is_enabled() )
		local _msg = fmt(" add_to_likely_scanner: calling w_m_portscan_new for %s, %s, %s", orig, service, resp);
		log_reporter(_msg, 0);

		event Scan::w_m_portscan_new(orig, service, resp, outbound);
@endif
	} # end if established 
}

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event Scan::w_m_portscan_new(orig: addr, service: port, resp: addr,
    outbound: bool)
{
	local msg = fmt(" inside w_m_portscan_new for %s, %s, %s", orig, service, resp);
	log_reporter(msg, 0);

	#if ( orig in Scan::known_scanners)
	if ( Scan::known_scanners[orig]$status ) {
		Scan::known_scanners[orig]$status = T;
		return;
	}

	if ( orig !in distinct_ports || service !in distinct_ports[orig] ) {
		if ( orig !in distinct_ports )
			distinct_ports[orig] = set();

		if ( service !in distinct_ports[orig] )
			add distinct_ports[orig][service];

		if ( |distinct_ports[orig]| >= possible_port_scan_thresh
		    && orig !in scan_triples ) {
			scan_triples[orig] = table();
			add possible_scan_sources[orig];
		}
	}

	local thresh_result=F;
	local troll_result = F;

	# Check for low ports.
	if ( activate_LowPortTrolling
	    && ! outbound
	    && service < 1024/tcp
	    && service !in troll_skip_service ) {
		#local troll_result = check_LowPortTroll(orig, service, resp);
		troll_result = F;
	}

	# For sources that have been identified as possible scan sources,
	# keep track of per-host scanning.
	if ( orig in possible_scan_sources ) {
		thresh_result = check_portscan_thresh(orig, service, resp);
	}

	if ( troll_result || thresh_result ) {
		local _msg = fmt("w_m_portscan_new: calling m_w_portscan_update_known_scanners for: %s, %s, %s", orig, service, resp);
		log_reporter(_msg, 0);

		event Scan::m_w_portscan_update_known_scanners(orig);

		if ( orig !in Scan::known_scanners ) {
			known_scanners[orig]$scanner = orig;
			Scan::known_scanners[orig]$status = T;
		}
	}
}
@endif

# we can get away with only sending orig here since thats what is used to update
# known_scanners table on workers , we are still sending d_port, resp
# for debugging assurances

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Scan::m_w_portscan_update_known_scanners(orig: addr)
{
	if ( orig !in Scan::known_scanners )
		Scan::known_scanners[orig]$status = T;

	local msg = fmt(
	    "portscan: added m_w_portscan_update_known_scanners for: %s, %s, %s", orig,
	    Scan::known_scanners[orig], |Scan::known_scanners[orig]|);
	log_reporter(msg, 0);
}
@endif
# events for scan detections

#event connection_established(c: connection)
#        {
#        local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#        Scan::check_PortScan(c, T, is_reverse_scan);
#
#        #local trans = get_port_transport_proto(c$id$orig_p);
#        #if ( trans == tcp && ! is_reverse_scan && TRW::use_TRW_algorithm )
#        #       TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event partial_connection(c: connection)
#        {
#        Scan::check_PortScan(c, T, F);
#        }
#
#event connection_attempt(c: connection)
#        {
#    local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#        Scan::check_PortScan(c, F, is_reverse_scan);
#
#        #local trans = get_port_transport_proto(c$id$orig_p);
#        #if ( trans == tcp && TRW::use_TRW_algorithm )
#        #       TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event connection_half_finished(c: connection)
#        {
#        # Half connections never were "established", so do scan-checking here.
#        Scan::check_PortScan(c, F, F);
#        }
#
#event connection_rejected(c: connection)
#        {
#        local is_reverse_scan = (c$orig$state == TCP_RESET && c$id$resp_p !in likely_server_ports);
#
#        Scan::check_PortScan(c, F, is_reverse_scan);
#
#        #local trans = get_port_transport_proto(c$id$orig_p);
#        #if ( trans == tcp && TRW::use_TRW_algorithm )
#        #       TRW::check_TRW_scan(c, conn_state(c, trans), is_reverse_scan);
#        }
#
#event connection_reset(c: connection)
#        {
#        if ( c$orig$state == TCP_INACTIVE || c$resp$state == TCP_INACTIVE )
#        {
#        local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#                # We never heard from one side - that looks like a scan.
#                Scan::check_PortScan(c, c$orig$size + c$resp$size > 0, is_reverse_scan);
#        }
#        }
#
#event connection_pending(c: connection)
#        {
#        if ( c$orig$state == TCP_PARTIAL && c$resp$state == TCP_INACTIVE )
#                Scan::check_PortScan(c, F, F);
#        }
#
#
