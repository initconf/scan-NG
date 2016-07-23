module Scan;

export {
	
	global Scan::add_to_known_scanners: function(orig: addr, detect: string); 

	global Scan::enable_scan_summary = T &redef ; 
	global Scan::use_catch_n_release = T &redef ; 

	global enable_big_tables = F &redef ; 

	 redef enum Notice::Type += {
                PasswordGuessing, 	# source tried many user/password combinations
                SuccessfulPasswordGuessing,     # same, but a login succeeded
		HotSubnet, 	# Too many scanners originating from this subnet 
        };

        type scan_info : record {
                        scanner: addr &log ;
                        status: bool &default=F ;
                        ###sport: port &log &optional ;
                        detection: string &log &optional &default="" ;
			detect_ts: time &default=double_to_time(0.0) ; 
                        event_peer: string &log &optional ;
                        expire: bool &default = F ;
                };

        global known_scanners_inactive: function(t: table[addr] of scan_info , idx: addr): interval;
        const known_scanners_create_expire: interval = 1 days ; # 20 mins ; 

        global known_scanners: table[addr] of scan_info &create_expire=known_scanners_create_expire
                                &expire_func=known_scanners_inactive ; 

	type conn_info: record {
		cid: conn_id ; 
		ts: time ; 
	} ; 


	#### used to identify when a scan started and how many hosts touched before detection 
	type start_ts: record { 
		ts: time &default=double_to_time(0.0); 
		conn_count: count &default=0 ; 
	} ; 
	
	global is_scanner: function (cid: conn_id): bool ;
	global is_darknet: function(ip: addr): bool  ;

	global table_start_ts: table[addr] of start_ts &read_expire=1 day ; 

	global ignored_scanners: set[addr] &create_expire = 1 day &redef;

	# helper functions
	global is_failed: function (c: connection): bool ; 
	global is_reverse_failed: function (c: connection): bool ; 
	global print_state: function (s: count, t: transport_proto): string ; 
		

	# TODO: Whether to consider UDP "connections" for scan detection.
	# Can lead to false positives due to UDP fanout from some P2P apps.
	const suppress_UDP_scan_checks = F &redef;
	

	# skip 
	global skip_services :set[port] = {} &redef;

	global skip_outbound_services: set[port]  = {} &redef;

	global skip_scan_sources: set[addr]  = {
		#255.255.255.255,	# who knows why we see these, but we do
	} &redef;

	global skip_scan_nets: set[subnet] = {} &redef;

	# List of well known local server/ports to exclude for scanning
	# purposes.
	global skip_dest_server_ports: set[addr, port] = {} &redef;


	global ignore_addr: function(a: addr); 
	global clear_addr: function (a: addr); 

	global hot_subnets: table[subnet] of set[addr] &create_expire=7 days; 
	global hot_subnets_idx: table[subnet] of count &create_expire=7 days; 
	global hot_subnets_threshold: vector of count = { 3, 10, 25, 100, 200, 255 } ; 
	

	global hot_subnet_check:function(ip: addr); 
	global check_subnet_threshold: function (v: vector of count, idx: table[subnet] of count, orig: subnet, n: count):bool ; 

}  #### end of export 


function is_darknet(ip: addr): bool
{

        ##### TODO: find a better place for this check
        #### since is_darknet will run for every c, we want it to be slim

#       if (|Site::subnet_table| == 0)
#       {
#               # since subnet table is zero size we poulate with local_nets
#               # by putting fake record for each local_nets
#
#               for (nets in Site::local_nets)
#               {
#                       Site:subnet_table[nets] = {nets, "0.0.0.0", "Site", "Filling the empty subnet table"};
#               }
#
#               return F ;
#       }

        if (Site::is_local_addr(ip) && ip !in Site::subnet_table)
                return T;

        return F ;

}

###### action to take when scanner is expiring 

function known_scanners_inactive(t: table[addr] of scan_info, idx: addr): interval
{
	log_reporter(fmt("known_scanners_inactive: %s", t[idx]),0); 
        #return 1 mins;
	
	### TODO: determine what we shall do when a known_scanners expire 	

	#if (idx in scan_summary)
	#	delete scan_summary[idx] ; 
		
	return 0 secs ; 
} 

function ignore_addr(a: addr)
	{
	clear_addr(a);
	add ignored_scanners[a];
	}


function clear_addr(a: addr)
{
        
	log_reporter(fmt ("scan-base: clear_addr : %s", a), 0);

	#if (a in known_scanners)
	#{
		#Scan::log_reporter(fmt ("deleted: known_scanner: %s, %s", a, Scan::known_scanners[a]),1);
		##event Scan::w_m_update_known_scan_stats(a, known_scanners[a]);
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
        if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
                (c$orig$state == TCP_SYN_SENT && c$resp$state ==  TCP_INACTIVE ) ||
             (((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
               (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history )
              ) && /[Dd]/ !in c$history )
           )
                return T;
        return F;
        }

function is_reverse_failed(c: connection): bool
        {
        # reverse scan i.e. conn dest is the scanner
        # sR || ( (Hr || sHr) && (data not sent in any direction) )
        if ( (c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET) ||
             (((c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT) ||
               (c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history )
              ) && /[Dd]/ !in c$history )
           )
                return T;
        return F;
        }

function print_state(s: count, t: transport_proto): string
{

        if (t == tcp ) {
        switch(s)
        {
                case 0: return "TCP_INACTIVE" ;
                case 1: return "TCP_SYN_SENT" ;
                case 2: return "TCP_SYN_ACK_SENT";
                case 3: return "TCP_PARTIAL" ;
                case 4: return "TCP_ESTABLISHED" ;
                case 5: return "TCP_CLOSED" ;
                case 6: return "TCP_RESET" ;
        };
        }

        if ( t == udp )
        {
                switch(s)
                {
                        case 0: return "UDP_INACTIVE" ;
                        case 1: return "UDP_ACTIVE" ;
                }
        }

        return "UNKNOWN" ;
}


event table_sizes()
{

	return ; 


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

	schedule 10 mins { table_sizes() } ; 

} 


function check_subnet_threshold(v: vector of count, idx: table[subnet] of count, orig: subnet, n: count):bool
{
	if (orig !in idx)
		idx[orig]=  0 ;

### print fmt ("orig: %s and IDX_orig: %s and n is: %s and v[idx[orig]] is: %s", orig, idx[orig], n, v[idx[orig]]);

	 if ( idx[orig] < |v| && n >= v[idx[orig]] )
                {
                ++idx[orig];

                return (T);
                }
        else
                return (F);
}

function hot_subnet_check(ip: addr)
{


	if (known_scanners[ip]$detection == "BackscatterSeen")
		return ; 


	 # check for subnet scanners
	 local scanner_subnet = mask_addr(ip, 24) ;

	if (scanner_subnet !in hot_subnets)
	{
		local a: set[addr]  ; 
		hot_subnets[scanner_subnet] = a ; 
	} 

	if (ip !in hot_subnets[scanner_subnet] ); 
		add hot_subnets[scanner_subnet][ip]; 
 
	local n = |hot_subnets[scanner_subnet]|  ; 
	
	local result = F ; 
	result = check_subnet_threshold(hot_subnets_threshold, hot_subnets_idx , scanner_subnet, n); 

	#### print fmt ("%s has %s scanners originating from it", scanner_subnet, n); 

	if (result)
	{ 
		local _msg = fmt ("%s has %s scanners originating from it", scanner_subnet, n); 
	
		NOTICE([$note=HotSubnet,  $src_peer=get_local_event_peer(), $src=ip, $msg=fmt("%s", _msg)]);
	} 

}
