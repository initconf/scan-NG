module Scan;

export {
	redef Config::config_files += {
		"/YURT/feeds/zeek-FP/Scan::scan-config.zeek"
	};

	# List of well known local server/ports to exclude for scanning
        # purposes. skips
        option skip_services: set[port] = { } &redef;
        option skip_outbound_services: set[port] = { } &redef;
        option skip_scan_nets: set[subnet] = { } &redef;
        option skip_dest_server_ports: set[addr, port] = { } &redef;
        option skip_scan_sources: set[addr] = { #255.255.255.255,       # who knows why we see these, but we do
        } &redef;


	option ignore_hot_subnets: set[subnet] = { [2620:0:28B0::]/44,} ;
	option ignore_hot_subnets_ports: set[port] = { 53/tcp, 853/tcp,};

	global Scan::add_to_known_scanners: function(orig: addr, detect: string);
	global Scan::enable_scan_summary = T &redef;
	global Scan::use_catch_n_release = T &redef;
	global enable_big_tables = F &redef;

	redef enum Notice::Type += {
		PasswordGuessing, # source tried many user/password combinations
		SuccessfulPasswordGuessing, # same, but a login succeeded
		DisableCatchRelease,
	};

	type scan_info: record {
		scanner: addr &log;
		status: bool &default=F;
		#sport: port &log &optional ;
		detection: string &log &optional &default="";
		detect_ts: time &default=double_to_time(0.0);
		event_peer: string &log &optional;
		expire: bool &default=F;
	};

	# we let only the manager manage deletion of the known_scanners on the worker
	# Reason: (i) we don't know separate timers for workers and managers for a scanner
	# (ii) unexpected absence of known_scanners can cause values to be wrong in scan_summary

	global finish_scan_summary: event(ip: addr);

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled() )
	global known_scanners_inactive: function(t: table[addr] of scan_info,
	    idx: addr): interval;
	const known_scanners_create_expire: interval = 1 day; # 20 mins ;
	global known_scanners: table[addr] of scan_info
	    &read_expire=known_scanners_create_expire
	    &expire_func=known_scanners_inactive;
@endif

	# workers will keep known_scanners until manager sends m_w_remove_scanner event
	# when manager calls known_scanners_inactive event

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
	global known_scanners: table[addr] of scan_info;
@endif

	type conn_info: record {
		cid: conn_id;
		ts: time;
	};

	# used to identify when a scan started and how many hosts touched before detection
	type start_ts: record {
		ts: time &default=double_to_time(0.0);
		conn_count: count &default=0;
	};

	global is_scanner: function(cid: conn_id): bool;
	global is_darknet: function(ip: addr): bool;
	global table_start_ts: table[addr] of start_ts &read_expire=1 hrs;
	global ignored_scanners: set[addr] &create_expire=1 day &redef;

	# helper functions
	global is_failed: function(c: connection): bool;
	global is_reverse_failed: function(c: connection): bool;
	global print_state: function(s: count, t: transport_proto): string;

	global ignore_addr: function(a: addr);
	global clear_addr: function(a: addr);
	global dont_drop: function(a: addr): bool;

	global can_drop_connectivity = F &redef;
	global dont_drop_locals = T &redef;
	global is_catch_release_active: function(ip: addr): bool;

	const never_drop_nets: set[subnet] &redef;

	# TODO: Whether to consider UDP "connections" for scan detection.
	# Can lead to false positives due to UDP fanout from some P2P apps.
	const suppress_UDP_scan_checks = F &redef;
	global whitelist_subnet: set[subnet] &backend=Broker::MEMORY;
	global whitelist: set[addr] &backend=Broker::MEMORY;
} # end of export

export {
	global Scan::m_w_add_scanner: event(ss: scan_info);
	global Scan::potential_scanner: event(ci: conn_info, established: bool,
	    reverse: bool, filtrator: string);
	global Scan::m_w_update_scanner: event(ip: addr, status_flag: bool);
	global Scan::w_m_update_scanner: event(ss: scan_info);
	global Scan::m_w_remove_scanner: event(ip: addr);

	global get_subnet:function (ip: addr):subnet;

}

#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /Scan::m_w_(add|remove|update)_scanner/;
#redef Cluster::worker2manager_events += /Scan::w_m_(new|add|remove|update)_scanner/;
#@endif


function get_subnet(ip: addr):subnet
{
        local scanner_subnet : subnet;

        if (is_v6_addr(ip))
                scanner_subnet = mask_addr(ip, 64);
        else
                scanner_subnet = mask_addr(ip, 24);

        return scanner_subnet;
}


@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
{
	Broker::auto_publish(Cluster::worker_topic, Scan::m_w_add_scanner);
	Broker::auto_publish(Cluster::worker_topic, Scan::m_w_remove_scanner);
	Broker::auto_publish(Cluster::worker_topic, Scan::m_w_update_scanner);
}
@else
event zeek_init()
{
	Broker::auto_publish(Cluster::manager_topic, Scan::potential_scanner);
	Broker::auto_publish(Cluster::manager_topic, Scan::w_m_update_scanner);
}
@endif

@endif

# Checks if a perticular connection is already blocked and managed by netcontrol
# and catch-and-release. If yes, we don't process this connection any-further in the
# scan-detection module
#
# ip: addr - ip address which needs to be checked
#
# Returns: bool - returns T or F depending if IP is managed by :bro:see:`NetControl::get_catch_release_info`

function is_catch_release_active(ip: addr): bool
{
	#if (gather_statistics)
	#        s_counters$is_catch_release_active += 1;

@ifdef ( NetControl::BlockInfo )
	local orig = ip;

	local bi: NetControl::BlockInfo;
	bi = NetControl::get_catch_release_info(orig);

	#log_reporter(fmt("is_catch_release_active: blockinfo is %s, %s", cid, bi),0);
	# if record bi is initialized
	if ( bi$watch_until != 0.0 )
		return T;

	# means empty bi
	# [block_until=<uninitialized>, watch_until=0.0, num_reblocked=0, current_interval=0, current_block_id=]

@endif

	return F;
}

function dont_drop(a: addr): bool
{
	return ! can_drop_connectivity
	    || a in never_drop_nets
	    || ( dont_drop_locals && Site::is_local_addr(a) );
}

function is_darknet(ip: addr): bool
{
	if ( Scan::SubnetCountToActivteLandMine != |Scan::subnet_table| )
		return F;

	if ( Site::is_local_addr(ip) && ip in Scan::allocated_cache )
		return F;

	if ( Site::is_local_addr(ip) && ip !in Scan::subnet_table )
		return T;

	return F;
}

# action to take when scanner is expiring

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled() )
function known_scanners_inactive(t: table[addr] of scan_info, idx: addr)
    : interval
{
	#log_reporter(fmt("known_scanners_inactive: %s", t[idx]),0);

	# sending message to all workers to delete this scanner
	# since its inactive now

	event Scan::m_w_remove_scanner(idx);
	schedule 30 secs { Scan::finish_scan_summary(idx) };

	# delete from the manager too

	return 0 secs;
}
@endif

function ignore_addr(a: addr)
{
	clear_addr(a);
	add ignored_scanners[a];
}

function clear_addr(a: addr)
{
	log_reporter(fmt("scan-base: clear_addr : %s", a), 0);

#if (a in known_scanners)
#{
#Scan::log_reporter(fmt ("deleted: known_scanner: %s, %s", a, Scan::known_scanners[a]),1);
#event Scan::w_m_update_known_scan_stats(a, known_scanners[a]);
#delete known_scanners[a];
#}

#if (a in distinct_peers)
#	delete distinct_peers[a];

#if (a in shut_down_thresh_reached)
#	delete shut_down_thresh_reached[a];

#if (a in backscatter)
#	delete backscatter[a];

#if (a in distinct_backscatter_peers)
#	delete distinct_backscatter_peers[a];

#if (a in likely_scanner)
#	delete likely_scanner[a] ;

#if ( a in landmine_distinct_peers)
#	delete landmine_distinct_peers[a] ;

#if (a in distinct_ports)
#	delete distinct_ports[a];

#if (a in distinct_low_ports)
#	delete distinct_low_ports[a];

#if (a in scan_triples)
#	delete scan_triples[a];

#if (a in rb_idx)
#	delete rb_idx[a];
#if (a in rps_idx)
#	delete rps_idx[a];
#if (a in rops_idx)
#	delete rops_idx[a];
#if (a in rat_idx)
#	delete rat_idx[a];
#if (a in rrat_idx)
#	delete rrat_idx[a];

#	delete possible_scan_source[a];
#	delete pre_distinct_peers[a];
#	delete ignored_scanners[a];
}

function is_failed(c: connection): bool
{
	# Sr || ( (hR || ShR) && (data not sent in any direction) )
	if ( ( c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET )
	    || ( c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_INACTIVE )
	    || ( ( ( c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT ) || ( c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history ) ) && /[Dd]/ !in c$history ) )
		return T;
	return F;
}

function is_reverse_failed(c: connection): bool
{
	# reverse scan i.e. conn dest is the scanner
	# sR || ( (Hr || sHr) && (data not sent in any direction) )
	if ( ( c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET )
	    || ( ( ( c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT ) || ( c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history ) ) && /[Dd]/ !in c$history ) )
		return T;
	return F;
}

function print_state(s: count, t: transport_proto): string
{
	if ( t == tcp ) {
		switch ( s ) {
			case 0:
				return "TCP_INACTIVE";
			case 1:
				return "TCP_SYN_SENT";
			case 2:
				return "TCP_SYN_ACK_SENT";
			case 3:
				return "TCP_PARTIAL";
			case 4:
				return "TCP_ESTABLISHED";
			case 5:
				return "TCP_CLOSED";
			case 6:
				return "TCP_RESET";
		}
		;
	}

	if ( t == udp ) {
		switch ( s ) {
			case 0:
				return "UDP_INACTIVE";
			case 1:
				return "UDP_ACTIVE";
		}
	}

	return "UNKNOWN";
}

event table_sizes()
{
	return;

	#log_reporter(fmt("table_size: backscatter: %s",|backscatter|),0);
	#log_reporter(fmt("table_size: conn_table: %s",|conn_table|),0);
	#log_reporter(fmt("table_size: distinct_backscatter_peers: %s",|distinct_backscatter_peers|),0);
	#log_reporter(fmt("table_size: distinct_low_ports: %s",|distinct_low_ports|),0);
	#log_reporter(fmt("table_size: distinct_peers: %s",|distinct_peers|),0);
	#log_reporter(fmt("table_size: distinct_ports: %s",|distinct_ports|),0);
	#log_reporter(fmt("table_size: done_with: %s",|done_with|),0);
	#log_reporter(fmt("table_size: expire_done_with: %s",|expire_done_with|),0);
	#log_reporter(fmt("table_size: host_profiles: %s",|Site::host_profiles|),0);
	#log_reporter(fmt("table_size: known_scanners: %s",|known_scanners|),0);
	#log_reporter(fmt("table_size: known_scanners_inactive: %s",|known_scanners_inactive|),0);
	#log_reporter(fmt("table_size: landmine_distinct_peers: %s",|landmine_distinct_peers|),0);
	#log_reporter(fmt("table_size: likely_scanner: %s",|likely_scanner|),0);
	#log_reporter(fmt("table_size: rat_idx: %s",|rat_idx|),0);
	#log_reporter(fmt("table_size: rb_idx: %s",|rb_idx|),0);
	#log_reporter(fmt("table_size: report_conn_stats: %s",|report_conn_stats|),0);
	#log_reporter(fmt("table_size: rops_idx: %s",|rops_idx|),0);
	#log_reporter(fmt("table_size: rps_idx: %s",|rps_idx|),0);
	#log_reporter(fmt("table_size: rpts_idx: %s",|rpts_idx|),0);
	#log_reporter(fmt("table_size: rrat_idx: %s",|rrat_idx|),0);
	#log_reporter(fmt("table_size: scan_triples: %s",|scan_triples|),0);
	#log_reporter(fmt("table_size: shut_down_thresh_reached: %s",|shut_down_thresh_reached|),0);
	#log_reporter(fmt("table_size: subnet_table: %s",|Site::subnet_table|),0);
	#log_reporter(fmt("table_size: thresh_check: %s",|thresh_check|),0);
	#log_reporter(fmt("table_size: uid_table: %s",|uid_table|),0);
	#log_reporter(fmt("table_size: whitelist_ip_table: %s",|whitelist_ip_table|),0);
	#log_reporter(fmt("table_size: whitelist_subnet_table: %s",|whitelist_subnet_table|),0);

	schedule 10 mins { table_sizes() };
}
