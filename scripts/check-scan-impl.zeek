module Scan;

export {
	global check_scan_cache: function(c: connection, established: bool,
	    reverse: bool, filtrator: string);
	global run_scan_detection: function(ci: conn_info, established: bool,
	    reverse: bool, filtrator: string): bool;
}

# Final function which calls various scan-detection heuristics, if activated
# as specificed in scan-user-config.bro
#
# ci: conn_info  - contains conn_id + first seen timestamp for the connection
# established: bool - if connection was established or not
# reverse: bool - if initial sy/ack was seen from the dst without a syn from orig
# filtrator: string  - consist of K(knockknock), L(LandMine), B(BackScatter), A(AddressScan)
# if any of the above filteration is true then based on filtrator string - that specific heuristic will
# be applied to the connection
#
# Returns: bool - returns T or F depending if IP is a scanner
function Scan::run_scan_detection(ci: conn_info, established: bool,
    reverse: bool, filtrator: string): bool
{
	if ( gather_statistics ) {
		s_counters$run_scan_detection += 1;
	}


	local cid = ci$cid;
	local orig = ci$cid$orig_h;

	local heuristic: string;

	if (activate_LandMine && "L" in filtrator && check_LandMine(cid, established, reverse)) {
	    heuristic = "LandMine";
	} else if (activate_SubnetKnock && "S" in filtrator && check_SubnetKnock(cid, established, reverse)) {
	    heuristic = "SubnetKnock";
	} else if (Scan::activate_KnockKnockScan && "K" in filtrator && check_KnockKnockScan(cid, established, reverse)) {
	    heuristic = "KnockKnockScan";
	} else if (Scan::activate_Backscatter && "B" in filtrator && Scan::check_Backscatter(cid, established, reverse)) {
	    heuristic = "Backscatter";
	} else if (activate_AddressScan && "A" in filtrator && check_AddressScan(cid, established, reverse)) {
	    heuristic = "AddressScan";
	} else if (activate_LowPortTrolling && "T" in filtrator && check_LowPortTroll(cid, established, reverse)) {
	    heuristic = "LowPortTrolling";
	} else {
	    return F;
	}

	# we should not consider Backscatter as scanners
	# So 


	if (heuristic != "Backscatter")
	{
		Scan::add_to_known_scanners(orig, heuristic);

		#adding a confirmed scanner to monitor its Subnet
		Scan::AddHotSubnet(orig);

		event Scan::PortSpike(cid$resp_p, orig);
	}

	#log_reporter (fmt("2. run_scan_detection: conn_info: %s, filterator: %s", ci, filtrator),0);
	return T;
}

function populate_table_start_ts(ci: conn_info)
{
	local orig = ci$cid$orig_h;

	if ( orig !in table_start_ts ) {
		local st: start_ts;
		table_start_ts[orig] = st;
		table_start_ts[orig]$ts = ci$ts;
	}

	table_start_ts[orig]$conn_count += 1;

	# gather the smallest timestamp for that IP
	# different workers see different ts

	if ( table_start_ts[orig]$ts > ci$ts )
		table_start_ts[orig]$ts = ci$ts;
}

# Entry point from check-scan function - this function dispatches connection to manager if cluster is enabled
# or calls run_scan_detection for standalone instances
# c: connection record
# established: bool - if connection is established
# reverse: bool -
# filtrator: string - comprises of K,L,A,B depending on which one of the filteration was successful
function check_scan_cache(c: connection, established: bool, reverse: bool,
    filtrator: string)
{
	if ( gather_statistics ) {
		s_counters$check_scan_cache += 1;
	}

	local orig = c$id$orig_h;
	local resp = c$id$resp_h;

	local ci: conn_info;

	ci$cid = c$id;
	ci$ts = c$start_time;

	#already identified as scanner no need to proceed further
	if ( orig in Scan::known_scanners && Scan::known_scanners[orig]$status ) {
		s_counters$check_scan_counter += 1;
		return;
	}

	# send to proxy and/or run_scan_detection 
@if ( Cluster::is_enabled() )
	local scan_sub=get_subnet(orig);
	Cluster::publish_hrw(Cluster::proxy_pool, scan_sub, Scan::potential_scanner, ci,
	    established, reverse, filtrator);
@else
	populate_table_start_ts(ci);
	#AddHotSubnet(orig);
	run_scan_detection(ci, established, reverse, filtrator);
@endif
}

# Event runs on manager in cluster setup. All the workers run check_scan_cache locally and
# dispatch conn_info to manager which aggregates the connections of a source IP and
# calls heuristics for scan-dection
# ci: conn_info - conn_id + timestamp
# established: bool - if connect was established
# reverse: bool
# filtrator: string - comprises of K,L,A,B depending on which one of the filteration was successful
# @if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::PROXY)
# @endif 

event Scan::potential_scanner(ci: conn_info, established: bool, reverse: bool,
    filtrator: string)
{
	if ( gather_statistics ) {
		s_counters$worker_to_manager_counter += 1;
	}

	#log_reporter(fmt("A in inside potential_scanner: %s, %s", ci, filtrator),0);

	local orig = ci$cid$orig_h;

	if (orig in Scan::known_scanners)
		return;

	#AddHotSubnet(orig);

	populate_table_start_ts(ci);
	local is_scan = Scan::run_scan_detection(ci, established, reverse, filtrator);

	# if successful scanner, dispatch it to all workers
	# this is needed to keep known_scanners table syncd on all workers
	if ( is_scan ) {
@if ( Cluster::is_enabled() )
		Broker::publish(Cluster::worker_topic, Scan::m_w_add_scanner,
		    known_scanners[orig]);
@else
		event Scan::m_w_add_scanner(known_scanners[orig]);
@endif
	}
}

# update workers with new scanner info

# @if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER)
# @endif

event Scan::m_w_add_scanner(ss: scan_info)
{
	#log_reporter(fmt ("check-scan-impl: m_w_add_scanner: %s", ss), 0);
	local orig = ss$scanner;
	local detection = ss$detection;

	if ( orig !in known_scanners ) {
		Scan::add_to_known_scanners(orig, detection);

		# send stats (start_ts, end_ts etc to manager
		if ( orig in worker_stats ) {
			worker_stats[orig]$detection = detection;

@if ( Cluster::is_enabled() )
			local scan_sub = get_subnet(orig);
			Cluster::publish_hrw(Cluster::proxy_pool, scan_sub, Scan::aggregate_scan_stats,
			    worker_stats[orig]);
@else
			event Scan::aggregate_scan_stats(worker_stats[orig]);
@endif
		}
	}
}

# populates known_scanners table and if scan_summary is enabled then
# handles initialization of scan_summary table as well.
# also logs first Detection entry in scan_summary
# orig: addr - IP address of scanner
# detect: string - what kind of scan was it - knock, address, landmine, backscatter
function Scan::add_to_known_scanners(orig: addr, detect: string)
{
	#log_reporter(fmt("3: Scanner found: [add_to_known_scanners]: orig: %s, detect: %s, %s", orig, detect, Cluster::node),0);

	# check if this scanner is a false positive 

	local new = F;

	if ( orig !in Scan::known_scanners ) {
		local si: scan_info;
		Scan::known_scanners[orig] = si;
		new = T;
	}

	Scan::known_scanners[orig]$scanner = orig;
	Scan::known_scanners[orig]$status = T;
	Scan::known_scanners[orig]$detection = detect;
	Scan::known_scanners[orig]$detect_ts = network_time();
	Scan::known_scanners[orig]$event_peer = fmt("%s", peer_description);

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || ( ! Cluster::is_enabled() ) )
	if ( orig in worker_stats )
		worker_stats[orig]$detection = detect;
@endif
#log_reporter(fmt("add_to_known_scanners: known_scanners[orig]: DETECT: %s, %s, %s, %s, %s", detect, orig, Scan::known_scanners [orig], network_time(), current_time()),0);
}
