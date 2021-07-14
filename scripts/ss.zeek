# code for scan-summary 
# aashish 

module Scan; 

export { 

	global scan_candidates: set[addr] &create_expire=1 day ; 

	# scan_summary module
        # authoritative table which keeps track of scanner 
	# status and statistics

	global LOGGING_TIME = 60 mins ; # 60 mins ; 
	global _max_expire_time = 4 hrs  ; # 1 day ; 
	global _worker_time = 10 mins ; # 1 day ; 

	type log_state: enum { DETECT, ONGOING, EXPIRE, UPDATE, FINISH, SUMMARY };
        type scan_stats : record {
                        scanner: addr &log ;
                	state: log_state  &default=DETECT ;
                        #status: bool &default=F ;
                        #sport: port &log &optional ;
                        detection: string &log &optional &default="" ;
                        start_ts: time &log &optional  &default=double_to_time(0.0);
                        end_ts: time &log &optional   &default=double_to_time(0.0);
                        detect_ts: time &log &optional  &default=double_to_time(0.0);
                        total_conn: count &default=0 &log ;
                        #hosts: set[addr] &log &optional ;
                        hosts: opaque of cardinality &default=hll_cardinality_init(0.1, 0.999);
                        #detect_count: count &log &optional &default=0;
			event_peer: string &log &optional ;
                };
	
@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (!Cluster::is_enabled()))

	global expire_worker_stats: function(t: table[addr] of scan_stats, idx: addr): interval ;  
	global worker_stats: table[addr] of scan_stats=table()
		 &create_expire=_worker_time &expire_func=expire_worker_stats ; 
@endif 

	global report_manager_stats: function(t: table[addr] of scan_stats, idx: addr): interval;
        global manager_stats: table[addr] of scan_stats=table()
                        &create_expire=20 secs   &expire_func=report_manager_stats ;

        #setting up logging for scan_summary.log
        redef enum Log::ID += { summary_LOG };

        type scan_stats_log: record {
                ts: time &default=network_time() &log ;
                scanner: addr &log ;
                state: log_state  &log &default=DETECT ;
                detection: string &log &optional &default="";
                start_ts: time &log &optional  &default=double_to_time(0.0);
                end_ts: time &log &optional  &default=double_to_time(0.0);
                detect_ts: time &log &optional  &default=double_to_time(0.0);
                detect_latency: interval &log &optional  ;
                total_conn: count &default=0 &log &optional ;
                total_hosts_scanned: count &default=0  &log &optional ;

                # computed value no need to store
                duration: interval &log &optional ;
                scan_rate: double &log &optional ;
                country_code: string &log &optional ;
                region: string &log &optional ;
                city: string &log &optional ;
                #geoip_info: geo_location &log &optional;
                distance: double &log &optional ;
                event_peer: string &log &optional ;
                };

	 global log_scan_summary:function (ss: scan_stats, state: log_state) ;
	 global aggregate_scan_stats: event(ss: scan_stats); 

        # Used for distance calculations
        global local_ip: addr = 128.3.0.0 &redef;
}


event zeek_init()
{
        when (local myaddrs = lookup_hostname(gethostname())) {
                for (ip in myaddrs) {
                        if (is_v4_addr(ip)) {
                                Scan::local_ip = ip;
                                local myloc = lookup_location(Scan::local_ip);
                                if (myloc?$city) {
                                        print fmt( "Using %s, %s as local location", 
								myloc$city, myloc$region);
                                }
                                break;
                        }
                }
        }
}

event zeek_init() &priority=5
{
        Log::create_stream(Scan::summary_LOG, [$columns=scan_stats_log]);
}


#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += // ;
#redef Cluster::worker2manager_events += /Scan::aggregate_scan_stats/;
#@endif

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::WORKER) 
event zeek_init()
        {
        Broker::auto_publish(Cluster::manager_topic, Scan::aggregate_scan_stats) ; 
        }
@endif

@endif 


@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (!Cluster::is_enabled()))
function Scan::expire_worker_stats(t: table[addr] of scan_stats, idx: addr): interval 
{ 


	if (idx in known_scanners)
	{ 
		#log_reporter(fmt("expire_worker_stats: sending to manager:  %s", t[idx]),10); 
		event Scan::aggregate_scan_stats(t[idx]); 
	} 
	else if (idx in scan_candidates && network_time() - t[idx]$start_ts < _max_expire_time ) 	
	{ 	
		#we just hold scan_candidate start time more in memory 
		# until its flagged as scanner - >= 1 conn/ day sensitivity 
		
		#log_reporter(fmt("expire_worker_stats: extended timer:  %s", t[idx]),10); 
		return _worker_time ;
	} 

	#log_reporter(fmt("expire_worker_stats: 0 secs:  %s", t[idx]),10); 
        return 0 secs;
} 
@endif 


# Entry function to scan_summary - this is called by check_scan.bro
#scan_summary(c: connection)

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (!Cluster::is_enabled()))
event connection_state_remove(c: connection) 
{ 
	local orig = c$id$orig_h ;
        local resp = c$id$resp_h ;
	local orig_p = c$id$orig_p ; 

        if (orig in Site::local_nets || orig_p == 7547/tcp  ) 
                return ;

	#if (orig !in scan_candidates)
	#	return ; 

        if (orig !in worker_stats)
        {
                local ss: scan_stats ;
                worker_stats[orig]=ss ;
                worker_stats[orig]$start_ts=c$start_time ;
		#worker_stats[orig]$hosts = set() ; 
        }

        worker_stats[orig]$scanner=orig ; 
        worker_stats[orig]$end_ts=c$start_time ;
        worker_stats[orig]$total_conn += 1 ;
        hll_cardinality_add(worker_stats[orig]$hosts, resp);
	#add worker_stats[orig]$hosts [resp] ; 
	
}
@endif 



function Scan::report_manager_stats(t: table[addr] of scan_stats, idx: addr): interval
{

	#log_reporter (fmt ("Running report_manager_stats: %s, size: %s", t[idx], |manager_stats|),10);
	if (idx in known_scanners)
	{
		if (t[idx]$state == DETECT)
		{
			log_scan_summary(t[idx], DETECT );
			t[idx]$state=UPDATE ;
		}
		else
		{
			log_scan_summary(t[idx], UPDATE);
		}
	} 

	# we need to expire slow scanners so either if end_ts is older than 1 day
	if (network_time() - t[idx]$end_ts > _max_expire_time )
	{ 
        	#log_reporter (fmt ("report_manager_stats: expiring: %s, size: %s", t[idx], |manager_stats|),10);
		log_scan_summary(t[idx], FINISH);
		return 0 secs ; 
	} 

        return LOGGING_TIME;
}

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || (!Cluster::is_enabled()))

event Scan::aggregate_scan_stats(ss: scan_stats)
{
        #log_reporter(fmt ("inside aggregate_scan_stats %s", ss),10);
        
	local orig = ss$scanner ;

	if ( orig !in known_scanners) 
		return ; 


	if (orig !in manager_stats)
       	{
               	local s: scan_stats;
               	manager_stats[orig]=s ;
               	manager_stats[orig]$scanner=orig;
		manager_stats[orig]$start_ts = ss$start_ts ; 
		manager_stats[orig]$end_ts = ss$end_ts ; 
		manager_stats[orig]$detect_ts = ss$end_ts ; 
		#manager_stats[orig]$hosts=set() ; 
	} 
		
	manager_stats[orig]$detection = known_scanners[orig]$detection ; 
        # update all the variables and aggregate based on what workers are returning

	local m_start_ts = manager_stats[orig]$start_ts ; 
	local m_end_ts = manager_stats[orig]$end_ts  ; 
	
        manager_stats[orig]$start_ts  = ss$start_ts < m_start_ts ? ss$start_ts : m_start_ts ;
        manager_stats[orig]$end_ts = ss$end_ts > m_end_ts ? ss$end_ts : m_end_ts  ;
        manager_stats[orig]$total_conn += ss$total_conn ;
	local peer = fmt("%s", Cluster::node ) ; 
	manager_stats[orig]$event_peer = fmt ("%s", Cluster::node);
        hll_cardinality_merge_into(manager_stats[orig]$hosts, ss$hosts );
	#for ( h in ss$hosts ) 
	#	add manager_stats[orig]$hosts [h]; 

        #log_reporter(fmt ("inside aggregate_scan_stats II  %s, size manager_stats: %s", manager_stats[orig], |manager_stats|),10);
}

function log_scan_summary(ss: scan_stats, state: log_state)
{

        #log_reporter(fmt("log_scan_summary: %s: state: %s", ss, state),5) ;

        local info: scan_stats_log ;

        #log_reporter(fmt("LSS: log_scan_summary: KS: %s, scan_summary: %s", known_scanners[ss$scanner],ss),5) ;
        # ash local detect_ts = known_scanners[ss$scanner]$detect_ts  ;

        # preserve detect_ts until scan_summary expires now
        if (ss$scanner in manager_stats)
                manager_stats[ss$scanner]$detect_ts = ss$detect_ts ;
        else
                log_reporter (fmt("ss$scanner not found in scan_summary : %s, %s", ss$scanner, ss),5);

	local scanner = ss$scanner ; 

        info$ts = network_time() ;
        info$scanner = scanner ; 
        info$state = state ;
        info$detection = ss$detection ;
        info$start_ts = ss$start_ts ;
        info$end_ts = ss$end_ts ;
        info$detect_ts = ss$detect_ts ;
        info$detect_latency = info$detect_ts - info$start_ts ;
        info$total_conn = ss$total_conn ;
        info$total_hosts_scanned = double_to_count(hll_cardinality_estimate(ss$hosts)); #|ss$hosts| ;
	#info$total_hosts_scanned = |ss$hosts|; 
        info$duration = info$end_ts - info$start_ts ; # ss$end_ts - ss$start_ts ;
        info$scan_rate = info$total_hosts_scanned == 0  ? 0 : interval_to_double(info$duration)/info$total_hosts_scanned ;
        local geoip_info = lookup_location(ss$scanner) ;
	local peer = Cluster::node; 
        info$event_peer = fmt ("%s", peer_description );


        info$country_code= geoip_info?$country_code ? geoip_info$country_code : ""  ;
        info$region = geoip_info?$region ? geoip_info$region : "" ;
        info$city = geoip_info?$city ? geoip_info$city : "" ;

        info$distance = 0 ;
        info$distance = haversine_distance_ip(Scan::local_ip, ss$scanner) ;
        #info$event_peer = ss$event_peer ;

        #log_reporter(fmt("log_scan_summary: info is : %s", info),5) ;

	Log::write(Scan::summary_LOG, info);
}

@endif 

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || (!Cluster::is_enabled()))
event finish_scan_summary(idx: addr)
{
	#log_reporter(fmt("finish_scan_summary: %s, %s", idx, manager_stats[idx]),10); 
	#log_scan_summary(manager_stats[idx], FINISH);
	#manager_stats[idx]$state =  FINISH;

} 
@endif 

