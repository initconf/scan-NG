module Scan;  

export {
	global check_scan_cache: function (c: connection, established: bool, reverse: bool, filtrator: string) ;
	global run_scan_detection: function(ci: conn_info, established: bool, reverse: bool, filtrator: string ): bool  ; 

	#global Scan::m_w_add_scanner: event (ss: scan_info) ; 
	#global Scan::w_m_new_scanner: event (ci: conn_info, established: bool, reverse: bool, filtrator: string); 
	#global Scan::m_w_update_scanner: event (ip: addr, status_flag: bool ); 
	#global Scan::w_m_update_scanner: event(ss: scan_info); 
	#global Scan::m_w_remove_scanner: event (ip: addr) ; 

} 

#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /Scan::m_w_(add|remove|update)_scanner/;
#redef Cluster::worker2manager_events += /Scan::w_m_(new|add|remove|update)_scanner/;
#@endif


## Final function which calls various scan-detection heuristics, if activated 
## as specificed in scan-user-config.bro 
##
## ci: conn_info  - contains conn_id + first seen timestamp for the connection
## established: bool - if connection was established or not 
## reverse: bool - if initial sy/ack was seen from the dst without a syn from orig 
## filtrator: string  - consist of K(knockknock), L(LandMine), B(BackScatter), A(AddressScan) 
## if any of the above filteration is true then based on filtrator string - that specific heuristic will
## be applied to the connection 
##
## Returns: bool - returns T or F depending if IP is a scanner
function Scan::run_scan_detection(ci: conn_info, established: bool, reverse: bool, filtrator: string ): bool 
{

	if (gather_statistics)
       	{
       		s_counters$run_scan_detection += 1;
       	}

	local cid=ci$cid ; 
	local orig=ci$cid$orig_h; 

	local result = F ; 
	if (activate_LandMine && /L/ in filtrator && check_LandMine(cid, established, reverse))
	{
		log_reporter (fmt("run_scan_detection: check_LandMine %s, %s", ci, filtrator),0); 
		Scan::add_to_known_scanners(orig, "LandMine"); 
	} 
	else if (Scan::activate_KnockKnockScan && /K/ in filtrator && check_KnockKnockScan(cid, established, reverse)) 
	{ 
		Scan::add_to_known_scanners(orig, "KnockKnockScan"); 
	} 
	else if (Scan::activate_BackscatterSeen &&  /B/ in filtrator && Scan::check_BackscatterSeen(cid, established, reverse))
	{

		Scan::add_to_known_scanners(orig, "BackscatterSeen");	
	} 
	else if (activate_AddressScan && /A/ in filtrator && check_AddressScan(cid, established, reverse)) 
	{
		Scan::add_to_known_scanners(orig, "AddressScan");
	} 
	else if (activate_LowPortTrolling && /T/ in filtrator && check_LowPortTroll(cid, established, reverse)) 
	{
		Scan::add_to_known_scanners(orig, "LowPortTrolling");
	} 
	else 
		return F ; 

	Scan::hot_subnet_check(orig); 

	return T ; 
}

####### clusterizations

#### main function to start sending data from worker to manager
### where manager will determine if scanner or not based on values
### collected from all the workers


function populate_table_start_ts(ci: conn_info)
{
	local orig=ci$cid$orig_h ; 

        if (orig !in table_start_ts)
        {
                local st: start_ts ;
                table_start_ts[orig] = st ;
                table_start_ts[orig]$ts = ci$ts ;
        }

        table_start_ts[orig]$conn_count += 1 ;

        ### gather the smallest timestamp for that IP
        ### different workers see different ts
        if (table_start_ts[orig]$ts > ci$ts)
                table_start_ts[orig]$ts  = ci$ts ;
} 


## Entry point from check-scan function - this function dispatches connection to manager if cluster is enabled 
## or calls run_scan_detection for standalone instances
## c: connection record
## established: bool - if connection is established 
## reverse: bool - 
## filtrator: string - comprises of K,L,A,B depending on which one of the filteration was successful
function check_scan_cache(c: connection, established: bool, reverse: bool, filtrator: string )
{


	if (gather_statistics)
	{
       		s_counters$check_scan_cache += 1;
	}

        local orig = c$id$orig_h ;
        local resp = c$id$resp_h;
	
	local ci: conn_info ;
	
	ci$cid = c$id ; 
	ci$ts = c$start_time; 
	
	# too expensive 
	### log_reporter(fmt("check_scan_cache: %s, filtrator is : %s", c$id, filtrator),0); 

        #already identified as scanner no need to proceed further 
        if (orig in Scan::known_scanners && Scan::known_scanners[orig]$status)
	{ 
       		s_counters$check_scan_counter += 1;
		#log_reporter(fmt("inside check_scan_cache: known_scanners[%s], %s", orig, known_scanners[orig]),0); 
                return;
	} 

	#### we run knockknockport local on each worker since portscan is too expensive 
	#### in term of traffic between nodes and its not worth this conjestion 
	

        ### if standalone then we check on bro node else we deligate manager to handle this
        @if ( Cluster::is_enabled() )
                #event Scan::w_m_new_scanner(ci, established, reverse, filtrator);
		Broker::publish(Cluster::manager_topic, Scan::w_m_new_scanner, ci, established, reverse, filtrator);
        @else
		populate_table_start_ts(ci); 
		run_scan_detection (ci, established, reverse, filtrator) ;
        @endif

}


## Event runs on manager in cluster setup. All the workers run check_scan_cache locally and 
## dispatch conn_info to manager which aggregates the connections of a source IP and 
## calls heuristics for scan-dection 
## ci: conn_info - conn_id + timestamp 
## established: bool - if connect was established 
## reverse: bool 
## filtrator: string - comprises of K,L,A,B depending on which one of the filteration was successful 
#@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )

event Scan::w_m_new_scanner(ci: conn_info, established: bool, reverse: bool, filtrator: string )
{
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
	if (gather_statistics)
       	{
       		s_counters$worker_to_manager_counter += 1;
	}
	
	#log_reporter(fmt("A in inside w_m_new_scanner: %s, %s", ci, filtrator),0); 

	local orig = ci$cid$orig_h ; 

	if (orig in Scan::known_scanners && Scan::known_scanners[orig]$status)
		return ; 

	populate_table_start_ts(ci); 

       	local result = Scan::run_scan_detection(ci, established, reverse, filtrator) ; 

		

	# if successful notify all workers of scanner 
	# so that they stop reporting further 
	# check for conn_history - that is if we ever saw a full SF going to this IP


@ifdef (History::check_conn_history)
        if (result && ! History::check_conn_history(orig) )
        {
		# if successful scanner, dispatch it to all workers 
		# this is needed to keep known_scanners table syncd on all workers 

		#event Scan::m_w_add_scanner(known_scanners[orig]); 
		Broker::publish(Cluster::worker_topic, Scan::m_w_add_scanner, known_scanners[orig]);
		
        }
@endif 

@endif
}
#@endif


### update workers with new scanner info
#@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )

event Scan::m_w_add_scanner (ss: scan_info) 
{
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
	#log_reporter(fmt ("check-scan-impl: m_w_add_scanner: %s", ss$scanner), 0);

	local orig = ss$scanner; 
	local detection = ss$detection ; 
        Scan::add_to_known_scanners(orig, detection );
@endif	
}
#@endif

## in the event when catch-n-release releases an IP - we change the known_scanners[ip]$status = F 
## so that workers again start sending conn_info to manager to reflag as scanner. 
#@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )

event Scan::w_m_update_scanner(ss: scan_info) 
{
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
	#log_reporter(fmt ("check-scan-impl: w_m_update_scanner: %s, %s", ss$scanner, ss$detection), 0);
	if ( ss$scanner !in Scan::known_scanners) 
	{ 
		Scan::add_to_known_scanners(ss$scanner, ss$detection); 
	} 

	### now that Manager added the worker reported portscan to its known_scanner
	#### manager needs to inform other workers of this new scanner 

	#event Scan::m_w_add_scanner(ss); 
	Broker::publish(Cluster::worker_topic, Scan::m_w_add_scanner, ss);
@endif	
} 

#@endif 

#@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )

event Scan::m_w_update_scanner (ip: addr, status_flag: bool )
{ 
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )

	#log_reporter(fmt ("check-scan-impl: m_w_update_scanner: %s, %s", ip, status_flag), 0);
	
	if (ip in known_scanners)
	{ 
		known_scanners[ip]$status = status_flag ; 
	} 
	else 
		log_reporter(fmt ("check-scan-impl: m_w_update_scanner: %s, %s NOT found in known_scanners - PROBLEM", ip, status_flag), 0);
@endif 

} 
#@endif 


#@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Scan::m_w_remove_scanner(ip: addr) 
{
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
	if (ip in known_scanners)
	{ 
		log_reporter(fmt("m_w_remove_scanner: %s", known_scanners[ip]),0); 
		delete known_scanners[ip] ; 
	} 
@endif 	
} 
#@endif 


## populates known_scanners table and if scan_summary is enabled then 
## handles initialization of scan_summary table as well. 
## also logs first Detection entry in scan_summary 
## orig: addr - IP address of scanner 
## detect: string - what kind of scan was it - knock, address, landmine, backscatter 
function Scan::add_to_known_scanners(orig: addr, detect: string)
{
	#log_reporter(fmt("function Scan::add_to_known_scanners: %s, %s", orig, detect),0); 

	local new = F ; 
        if (orig !in Scan::known_scanners)
        {
                local si: scan_info;
                Scan::known_scanners[orig] = si ;
		new = T ; 
        }
                Scan::known_scanners[orig]$scanner=orig;
                Scan::known_scanners[orig]$status = T ;
                Scan::known_scanners[orig]$detection = detect ;
		Scan::known_scanners[orig]$detect_ts = network_time(); 
                Scan::known_scanners[orig]$event_peer = fmt ("%s", peer_description);
        
		#log_reporter(fmt("add_to_known_scanners: known_scanners[orig]: DETECT: %s, %s, %s, %s, %s", detect, orig, Scan::known_scanners [orig], network_time(), current_time()),0);


	###populate scan_summary 
	if (enable_scan_summary)
	{
		if (orig !in Scan::scan_summary)
		{
                local ss: scan_stats;
                #local hh : set[addr];
                Scan::scan_summary[orig] = ss ;
                #Scan::scan_summary[orig]$hosts=hh ;
		}  

                Scan::scan_summary[orig]$scanner=orig;
                Scan::scan_summary[orig]$status = T ;
                Scan::scan_summary[orig]$detection = detect ;
                Scan::scan_summary[orig]$detect_ts = network_time();
                #Scan::scan_summary[orig]$detect_ts = current_time();
                Scan::scan_summary[orig]$event_peer = fmt ("%s", peer_description);

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| (! Cluster::is_enabled()))
		if (new)
		{ 
			#log_scan_summary(known_scanners[orig], DETECT) ; 
			log_scan_summary(scan_summary[orig], DETECT) ; 
		} 
@endif 

	}  # if enable_scan_summary 


}

