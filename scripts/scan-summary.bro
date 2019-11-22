module Scan ;

@load ./debug.bro 

@ifndef(zeek_init)
#Running on old bro that doesn't know about zeek events
global zeek_init: event();
event bro_init()
{
    event zeek_init();
}
@endif
	
#redef exit_only_after_terminate = T ; 

export {

	#global enable_scan_summary= T &redef ; 

	type log_state: enum { DETECT, ONGOING, EXPIRE, UPDATE, FINISH, SUMMARY };
	
	#### setting up logging for scan_summary.log 
	redef enum Log::ID += { summary_LOG }; 
	type scan_stats_log: record { 
		ts: time &default=network_time() &log ; 
		scanner: addr &log ;
		state: log_state  &log ; 
		detection: string &log &optional &default="";
                start_ts: time &log &optional  &default=double_to_time(0.0); 
                end_ts: time &log &optional  &default=double_to_time(0.0); 
                detect_ts: time &log &optional  &default=double_to_time(0.0); 
                detect_latency: interval &log &optional  ; 
                total_conn: count &default=0 &log &optional ;
                total_hosts_scanned: count &default=0  &log &optional ;

                ### computed value no need to store
               	duration: interval &log &optional ;
               	scan_rate: double &log &optional ;
		country_code: string &log &optional ; 
		region: string &log &optional ; 
		city: string &log &optional ; 
                #geoip_info: geo_location &log &optional;
                distance: double &log &optional ;
		event_peer: string &log &optional ; 
                };

	#### connection table 
	#### tmp buffer to record, start/end time and  what hosts were connected to

	type conn_stats: record { 
		start_ts: time  &default=double_to_time(0.0); 
		end_ts: time    &default=double_to_time(0.0); 
		hosts: opaque of cardinality &default=hll_cardinality_init(0.1, 0.99);
		conn_count: count &default=0; 
	} ; 

	const conn_table_create_expire: interval = 20 mins &redef; 

        global report_conn_stats: function(t: table[addr] of conn_stats, idx: addr): interval;
	global conn_table: table[addr] of conn_stats 
			&create_expire=conn_table_create_expire &expire_func=report_conn_stats ; 

        ########### scan_summary module
        # authoritative table which keeps track of scanner status and statistics
        ####
        type scan_stats : record {
			scanner: addr &log ;
			status: bool &default=F ; 
			#sport: port &log &optional ;
			detection: string &log &optional &default="" ;
			start_ts: time &log &optional  &default=double_to_time(0.0); 
			end_ts: time &log &optional   &default=double_to_time(0.0); 
			detect_ts: time &log &optional  &default=double_to_time(0.0); 
			total_conn: count &default=0 &log ;
			#hosts: set[addr] &log &optional ;
			hosts: opaque of cardinality &default=hll_cardinality_init(0.1, 0.99); 
			event_peer: string &log &optional ; 
			expire: bool &default = F ; 
			detect_count: count &log &optional &default=0; 
                };

	const scan_summary_read_expire: interval =  60 mins &redef ; 

        global scan_summary_inactive: function(t: table[addr] of scan_stats, idx: addr): interval;

        global scan_summary: table[addr] of scan_stats &create_expire=scan_summary_read_expire
                                &expire_func=scan_summary_inactive ; 
	
	const scan_summary_update_interval: interval =  60 mins &redef ; 
	const scan_summary_finish_interval: interval =  1 mins &redef ; 

	#########


	global m_w_send_scan_summary_stats: event (scanner: addr, send_status: bool ); 
	global w_m_update_scan_summary_stats: event (scanner: addr, stats: scan_stats); 

	global update_scan_summary_stats: function(idx: addr, stats: scan_stats); 
	global workers_update_scan_summary: function(idx: addr); 
	global manager_update_scan_summary: function(idx: addr, stats: scan_stats) ; 
	

	global log_scan_summary:function (ss: scan_stats, state: log_state) ; 
} 


event zeek_init() &priority=5 
{
	Log::create_stream(Scan::summary_LOG, [$columns=scan_stats_log]); 
} 


#function initialize_scan_summary(idx: addr): scan_stats 
function initialize_scan_summary(idx: addr)
{
	if (idx !in Scan::scan_summary)
        {
                local ss: scan_stats;
                ##local hh : set[addr];
                Scan::scan_summary[idx] = ss ;
                ##Scan::scan_summary[idx]$hosts=hh ;
                scan_summary[idx]$scanner=idx ;
                scan_summary[idx]$status= F ;
        }

	#return scan_summary[idx] ; 
	return ; 
} 


##### expire_func for conn_table to update or populate scan_summary on workers 

#@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER ) 
function report_conn_stats(t: table[addr] of conn_stats, idx: addr): interval 
{ 
	if (idx in Scan::known_scanners) 
	{ 
		#log_reporter (fmt ("report_conn_stats for calling update_scan_summary_counts %s: %s", idx, t[idx]),5); 
		workers_update_scan_summary(idx); 
	} 

	### TODO if not in scan_summary - its not a scanner 

	return 0 sec ; 
} 
#@endif 


### accumulate scan_summary on workers for and report to the manager 
function scan_summary_inactive(t: table[addr] of scan_stats, idx: addr): interval
{

### may be was a bad idea below but now resorting to this 

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
	workers_update_scan_summary(idx); 
	#event Scan::w_m_update_scan_summary_stats(idx, t[idx]); 
	Broker::publish(Cluster::manager_topic, Scan::w_m_update_scan_summary_stats, idx, t[idx]);
	
	return 0 sec ; 

@endif 


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ( !  Cluster::is_enabled()))

        #### update scan_summary table on the manager now
        #### based on all the data supplied by the workers

        #log_reporter(fmt("Manager : scan_summary_inactive: scan_summary: detect_ts: %s, known_scanners: detect_ts: %s for %s", scan_summary[idx]$detect_ts, known_scanners[idx]$detect_ts, idx),5);
        ### expire scan_summary entry

         #### convoluted expire
               if (! t[idx]$expire)
               {
			### check if not a known_scanner anymore we delete from scan_summary else extend logging 
			if (idx in known_scanners) 
			{ 
				#log_reporter(fmt("expiring scan_summary 1 mins  for %s", t[idx]),5);
	
				if (t[idx]$start_ts != 0.0) 	
					log_scan_summary(t[idx], UPDATE);

                       		return scan_summary_update_interval ; ### 60 mins 
			} 
			else 	
			{ 
				log_scan_summary(t[idx], FINISH);

				#if (t[idx]$start_ts != 0.0) 	
				#	log_scan_summary(t[idx], FINISH);

                       		t[idx]$expire = T ;
				return scan_summary_finish_interval ; ### 1 mins ; 
			} 
               	}
		### we need to extend for a min since all managers/worker times of table creation aren't 
		### quite synced so expire_function triggers at different times. 
               else
               {
			#log_reporter(fmt("deleting scan_summary permanently for %s", t[idx]),5);
			return 0 secs ;
               }
@endif


	return 0 sec ; 
} 

#### This is an important function we need to get this right 

function workers_update_scan_summary(idx: addr)
{

	if (idx !in Scan::scan_summary)
	{
                local ss: scan_stats;
                Scan::scan_summary[idx] = ss ;
       	}

	Scan::scan_summary[idx]$scanner=known_scanners[idx]$scanner; 
	Scan::scan_summary[idx]$status =known_scanners[idx]$status ; 
	Scan::scan_summary[idx]$detection=known_scanners[idx]$detection; 
	Scan::scan_summary[idx]$event_peer = fmt ("%s", peer_description);


 if (idx in Scan::scan_summary)
	{ 
	####log_reporter(fmt("workers_update_scan_summary: begin idx in scan_summary: %s, %s", idx, scan_summary[idx]),5) ; 
	if (idx in conn_table) 
        {

		### we want to make sure that only manager mantains the detect_ts 
		### and thats what is updated to scan_summary - unless standalone  

                scan_summary[idx]$total_conn += conn_table[idx]$conn_count ;
	
		hll_cardinality_merge_into(scan_summary[idx]$hosts, conn_table[idx]$hosts); 

		#local peer = get_event_peer()  ;
		scan_summary[idx]$event_peer = fmt ("%s", peer_description ); 

		 local zero_time = double_to_time(0.0);
                if (conn_table[idx]$start_ts > zero_time) {
                        if (scan_summary[idx]$start_ts != zero_time)
                        { scan_summary[idx]$start_ts = scan_summary[idx]$start_ts < conn_table[idx]$start_ts ? scan_summary[idx]$start_ts : conn_table[idx]$start_ts ; }
                        else { scan_summary[idx]$start_ts = scan_summary[idx]$start_ts > conn_table[idx]$start_ts ? scan_summary[idx]$start_ts : conn_table[idx]$start_ts ; }
                }

                if (conn_table[idx]$end_ts > zero_time) {
                        if (scan_summary[idx]$end_ts != zero_time)
                        { scan_summary[idx]$end_ts = scan_summary[idx]$end_ts > conn_table[idx]$end_ts ? scan_summary[idx]$end_ts : conn_table[idx]$end_ts ; }
                        else { scan_summary[idx]$end_ts = scan_summary[idx]$end_ts > conn_table[idx]$end_ts ? scan_summary[idx]$end_ts : conn_table[idx]$end_ts ; }
                }

		#### log_reporter(fmt("update_scan_summary_counts: end idx in scan_summary: %s, %s", idx, scan_summary[idx]),5) ; 
		#########

	} 
	#else
	#	 log_reporter(fmt("update_scan_summary_counts: idx NOT conn_table: %s", idx),5) ; 
	} 
 #else
 #{
 #	log_reporter(fmt("update_scan_summary_counts: idx NOT scan_summary: %s", idx),5) ; 
 #}

} 

function log_scan_summary(ss: scan_stats, state: log_state) 
{

	#log_reporter(fmt("log_scan_summary: %s: state: %s", ss, state),5) ; 

	local info: scan_stats_log ; 

	#### log_reporter(fmt("LSS: log_scan_summary: KS: %s, scan_summary: %s, ss: %s", known_scanners[ss$scanner], scan_summary[ss$scanner], ss),5) ; 

	### ash local detect_ts = known_scanners[ss$scanner]$detect_ts  ; 
	
	### preserve detect_ts until scan_summary expires now 
	if (ss$scanner in scan_summary)
		scan_summary[ss$scanner]$detect_ts = ss$detect_ts ; 
	else 
		log_reporter (fmt("ss$scanner not found in scan_summary : %s, %s", ss$scanner, ss),5); 

	info$ts = network_time() ; 
	info$scanner = ss$scanner; 
	info$state = state ; 
	info$detection = ss$detection ; 
	info$start_ts = state == DETECT ? table_start_ts[ss$scanner]$ts : ss$start_ts ;  
	info$end_ts = state == DETECT ? ss$detect_ts : ss$end_ts ; 
	info$detect_ts = ss$detect_ts ; 
	info$detect_latency = info$detect_ts - info$start_ts ;
	info$total_conn = state == DETECT ? table_start_ts[ss$scanner]$conn_count : ss$total_conn ; 
	info$total_hosts_scanned = state == DETECT ? table_start_ts[ss$scanner]$conn_count : double_to_count(hll_cardinality_estimate(ss$hosts)); #|ss$hosts| ; 
	info$duration = info$end_ts - info$start_ts ; ### ss$end_ts - ss$start_ts ;
	info$scan_rate = info$total_hosts_scanned == 0  ? 0 : interval_to_double(info$duration)/info$total_hosts_scanned ; 
	local geoip_info = lookup_location(ss$scanner) ;


	info$country_code=geoip_info$country_code ; 	
	info$region = geoip_info?$region ? geoip_info$region : "" ; 
	info$city = geoip_info?$city ? geoip_info$city : "" ; 
 
	info$distance = 0 ; 
	info$distance = haversine_distance_ip(128.3.0.0, ss$scanner) ; 

	info$event_peer = ss$event_peer ; 

	#log_reporter(fmt("log_scan_summary: info is : %s", info),5) ; 

	Log::write(Scan::summary_LOG, info); 
} 


@if (  Cluster::is_enabled() )
@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /Scan::m_w_send_scan_summary_stats/ ; 
#redef Cluster::worker2manager_events += /Scan::w_m_update_scan_summary_stats/ ; 
@endif 


function manager_update_scan_summary(idx: addr, stats: scan_stats) 
{

# [scanner=59.2.81.142, status=T, detection=<uninitialized>, start_ts=1461631108.377363, end_ts=1461631256.282214, detect_ts=0.0, total_conn=7, event_peer=worker-2]

#log_reporter(fmt ("Got STATS w_m_update_scan_summary_stats %s, %s", idx, stats ),5);
#log_reporter(fmt ("begin scan_summary Got STATS manager scan_summary looks like  %s, %s", idx, scan_summary[idx]),5);

        if (idx !in scan_summary)
        {
                local ss: scan_stats;
                Scan::scan_summary[idx] = ss ;
        }

	if (idx in scan_summary)
	{ 
		if (scan_summary[idx]$detect_ts ==0.0)
		scan_summary[idx]$detect_ts = known_scanners[idx]$detect_ts ; 

		 ### we don't need this since scan_summary is initialized on both workers and manager 
		 ### scan_summary[idx]$scanner=stats$scanner ;
		 ### Scan::scan_summary[idx]$detection = stats?$detection ? stats$detection : known_scanners[idx]$detection ;

		 ### get the latest status flag 
		 scan_summary[idx]$status= stats$status ;

		 ### add to the previous counts 
		Scan::scan_summary[idx]$total_conn = Scan::scan_summary[idx]$total_conn + stats$total_conn;

	        Scan::scan_summary[idx]$event_peer = stats?$event_peer ? stats$event_peer : fmt ("");

		hll_cardinality_merge_into(scan_summary[idx]$hosts, stats$hosts); 

	        local zero_time = double_to_time(0.0);
	        local prev_end_ts = scan_summary[idx]$end_ts ;
	
		 ### get the minimal start_time based on inputs from workers 
		if (stats$start_ts > zero_time) {
			if (scan_summary[idx]$start_ts != zero_time)
			{ scan_summary[idx]$start_ts = scan_summary[idx]$start_ts < stats$start_ts ? scan_summary[idx]$start_ts : stats$start_ts ; }
			else 
			{ scan_summary[idx]$start_ts = scan_summary[idx]$start_ts > stats$start_ts ? scan_summary[idx]$start_ts: stats$start_ts ; }
		}
	
		 #### get the maximum end_time based on inputs from workers 
		if (stats$end_ts > zero_time) 
		{
			scan_summary[idx]$end_ts = scan_summary[idx]$end_ts > stats$end_ts ? scan_summary[idx]$end_ts : stats$end_ts ;
	       	}
	} 
	 

	### log_reporter(fmt ("end scan_summary Got STATS manager scan_summary looks like  %s, %s", idx, scan_summary[idx]), 0);

}

#@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )  || (! Cluster::is_enabled()) ) 
event Scan::w_m_update_scan_summary_stats(idx: addr, stats: scan_stats)
{
@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )  || (! Cluster::is_enabled()) ) 
	#log_reporter(fmt("scan-summary->w_m_update_scan_summary_stats got stats %s for %s", stats, idx),5); 

	if (idx in known_scanners)
		manager_update_scan_summary(idx, stats); 
@endif
}
#@endif

#@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (! Cluster::is_enabled()) )
event Scan::m_w_send_scan_summary_stats(scanner: addr, send_status: bool )
{
@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER ) || (! Cluster::is_enabled()) )
	return ; 
@endif
} 

#@endif



event new_connection(c: connection)
{
	local orig = c$id$orig_h ;
	local resp = c$id$resp_h ; 
	local service = c$id$resp_p ; 

	# no need to track local IP .. yet 
	if (Site::is_local_addr(orig))
		return ; 		

	if (orig !in conn_table)
	{ 
		local cs: conn_stats; 
		conn_table[orig]=cs ; 
		conn_table[orig]$start_ts=c$start_time; 
	} 

	conn_table[orig]$end_ts=c$start_time; 
	conn_table[orig]$conn_count +=1 ; 

	#if (resp !in conn_table[orig]$hosts)
	#	add conn_table[orig]$hosts[resp] ; 

	hll_cardinality_add(conn_table[orig]$hosts, resp); 

	#log_reporter(fmt ("%s conn_table: %s", orig, conn_table[orig]),5); 
} 

##################### ##[id=[orig_h=192.12.15.26, orig_p=9808/udp, resp_h=131.243.187.37, resp_p=9542/udp], orig=[size=14, state=1, num_pkts=1, num_bytes_ip=42, flow_label=0], resp=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0], start_time=1461433882.027072, duration=0.0, service={\x0a\x0a}, history=D, uid=C0p9tNB9mzG4gjQjf, tunnel=<uninitialized>, dpd=<uninitialized>, conn=<uninitialized>, extract_orig=F, extract_resp=F, thresholds=<uninitialized>, dhcp=<uninitialized>, dnp3=<uninitialized>, dns=<uninitialized>, dns_state=<uninitialized>, ftp=<uninitialized>, ftp_data_reuse=F, ssl=<uninitialized>, http=<uninitialized>, http_state=<uninitialized>, irc=<uninitialized>, krb=<uninitialized>, modbus=<uninitialized>, mysql=<uninitialized>, radius=<uninitialized>, rdp=<uninitialized>, sip=<uninitialized>, sip_state=<uninitialized>, snmp=<uninitialized>, smtp=<uninitialized>, smtp_state=<uninitialized>, socks=<uninitialized>, ssh=<uninitialized>, syslog=<uninitialized>]
