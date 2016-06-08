### module to build network profile for scan detection 
### this module builds the 'ground-truth' ie prepares the list 
### legit LBNL servers and ports based on incoming SF.
### premise: if external IP connecting to something not in this list
### is likely a scan if (1) incoming connections meet fanout criteria 

### basically, the script works like this: 
### src: knock .
### src: knock ..	
### src: knock ...
### bro: bye-bye !!! 

### todo: 
### a. need backscatter identification (same src port diff dst port for scanner
### b. address 80/tcp, 443/tcp, 861/tcp, 389/tcp (sticky config)  - knock_high_threshold_ports 
### c. GeoIP integration - different treatment to > 130 miles IP vs US IPs vs Non-US IPs
### d. False +ve suppression and statistics _


module Scan;

#redef exit_only_after_terminate=F;

export {

	global activate_KnockKnockScan = F &redef ; 
	
	redef enum Notice::Type += {
                KnockKnockScan, # source flagged as scanner by TRW algorithm
                KnockKnockSummary, # summary of scanning activities reported by TRW
		LikelyScanner, 
		IgnoreLikelyScanner, 
		KnockSummary, 

        };
	
	 # sensitive and sticky config ports
        global knock_high_threshold_ports: set[port] = { 861/tcp, 80/tcp, 443/tcp, 8443/tcp, 8080/tcp } &redef ;

        global knock_medium_threshold_ports: set[port] = { 	17500/tcp,  # dropbox-lan-sync
                                                    		135/tcp, 139/tcp, 445/tcp,
                                                       		 0/tcp, 389/tcp, 88/tcp,
                                                       		 3268/tcp, 52311/tcp,
                                                    } &redef ;

        #redef knock_high_threshold_ports += { 113/tcp, 636/tcp, 135/tcp, 139/tcp, 17500/tcp, 18457/tcp,
        #                                3268/tcp, 3389/tcp, 3832/tcp, 389/tcp,
        #                                4242/tcp, 443/tcp, 445/tcp, 52311/tcp, 5900/tcp,
        #                                60244/tcp, 60697/tcp, 80/tcp, 8080/tcp, 7000/tcp, 8192/tcp,
        #                                8194/tcp, 8443/tcp, 88/tcp, 9001/tcp,
        #                                };

	# scan candidate 
	global likely_scanner: table[addr,port] of set[addr] &read_expire=1 day ; ### &synchronized ; 
	
	global c_likely_scanner: table[addr,port] of opaque of cardinality
                &default = function(a:addr, p:port): opaque of cardinality { return hll_cardinality_init(0.1, 0.99); }
		&read_expire=1 day  ; 

	global HIGH_THRESHOLD_LIMIT= 12 &redef ; 
	global MED_THRESHOLD_LIMIT=5 &redef ;
	global LOW_THRESHOLD_LIMIT=3 &redef ; 

	global COMMUTE_DISTANCE = 320 &redef ; 

	# automated_exceptions using input-framework
	#global ipportexclude_file  = "/usr/local/bro-cpp/common/feeds/knockknock.exceptions" &redef ;
	global ipportexclude_file  = "/YURT/feeds/BRO-feeds/knockknock.exceptions" &redef ;

        type ipportexclude_Idx: record {
                exclude_ip: addr;
                exclude_port: port &type_column="t";
        };
        type ipportexclude_Val: record {
                exclude_ip: addr;
                exclude_port: port &type_column="t" ;
                comment: string &optional ;
        } ;

	global ipportexclude: table[addr, port] of ipportexclude_Val = table() &redef  ; ### &synchronized ;
	global concurrent_scanners_per_port: table[port] of set[addr] &write_expire=6 hrs ; #### &synchronized ; 
	
	### clusterization helper events 
	global m_w_knockscan_add: event (orig: addr, d_port: port,  resp: addr);
	global w_m_knockscan_new: event (orig: addr, d_port: port,  resp: addr);
	global add_to_knockknock_cache: function(orig: addr, d_port: port,  resp: addr);

	global check_knockknock_scan: function(orig: addr, d_port: port, resp: addr): bool  ; 
	global check_KnockKnockScan: function(cid: conn_id, established: bool, reverse: bool ): bool; 

	global validate_KnockKnockScan: function (c: connection, darknet: bool ): string ; 
}


function check_knockknock_scan(orig: addr, d_port: port, resp: addr): bool 
{

	if (gather_statistics)
		s_counters$c_knock_core += 1  ; 

	local result = F ; 
	
	local high_threshold_flag=F ;
	local medium_threshold_flag=F; 
	local usual_threshold_flag=F; 

        # # # # # ## # # # # #
        # code and heuristics of to determine if orig is inface a scanner

	# gather geoip distance
        local orig_loc = lookup_location(orig);
        local resp_loc = lookup_location(resp);

	local distance = 0.0 ; 
        #distance = get_haversine_distance(orig, resp);

        # if driving distance, we raise the block threshold
        # 6 hours - covers tahoe and Yosemite from berkeley
        if (distance < COMMUTE_DISTANCE )
        {
                high_threshold_flag =  F;
        }

        if (d_port !in concurrent_scanners_per_port)
        {
                concurrent_scanners_per_port[d_port]=set();
        }

        # stop populating the table if > 6 simultenious scanners
        # are probing on the same port. IN this case we
        # reduce the threshold to 3 faolures to block
        if (|concurrent_scanners_per_port[d_port]| <=5) {
                add concurrent_scanners_per_port[d_port][orig] ;
        }


	
        # check if in knock_high_threshold_ports or rare port scan (too few concurrent scanners)
        # notch up threshold ot high  - likewise for medium thresholds

        if (d_port in knock_high_threshold_ports  || |concurrent_scanners_per_port[d_port]| <=2)
        {       high_threshold_flag = T ; }
        else if (d_port in knock_medium_threshold_ports  || |concurrent_scanners_per_port[d_port]| <=5)
        {       medium_threshold_flag = T ;  }


#	if (orig !in Scan::known_scanners) 
#        {
#                if (|likely_scanner[orig,d_port]| == HIGH_THRESHOLD_LIMIT && high_threshold_flag )
#                {
#			result = T ; 
#                }
#                else if (|likely_scanner[orig,d_port]| == MED_THRESHOLD_LIMIT && medium_threshold_flag )
#                {
#			result = T ; 
#                }
#                else if (|likely_scanner[orig,d_port]| >= LOW_THRESHOLD_LIMIT && !high_threshold_flag && !medium_threshold_flag)
#                {
#			result = T ; 
#                }
#	} 
	
	
       if (orig !in Scan::known_scanners)
        {
		local d_val = double_to_count(hll_cardinality_estimate(c_likely_scanner[orig,d_port])) ; 

                if (d_val == HIGH_THRESHOLD_LIMIT && high_threshold_flag )
                {
                       result = T ;
                }
                else if (d_val == MED_THRESHOLD_LIMIT && medium_threshold_flag )
                {
                       result = T ;
                }
                else if (d_val >= LOW_THRESHOLD_LIMIT && !high_threshold_flag && !medium_threshold_flag)
                {
                       result = T ;
                }
       }

		if (result) 
		{ 
		# make sure there is country code
		local cc =  orig_loc?$country_code ? orig_loc$country_code : "" ;

               	# build list of hosts touched

               	local hosts_probed ="" ;

               	#for (a in likely_scanner[orig,d_port])
               	#	hosts_probed += fmt (" %s ", a);

		#local _msg = fmt("%s scanned a total of %d hosts: [%s] (port-flux-density: %s) (origin: %s distance: %.2f miles) on %s", orig, |likely_scanner[orig,d_port]|,d_port, |concurrent_scanners_per_port[d_port]|, cc, distance, hosts_probed);
		local _msg = fmt("%s scanned a total of %d hosts: [%s] (port-flux-density: %s) (origin: %s distance: %.2f miles) on %s", orig, d_val,d_port, |concurrent_scanners_per_port[d_port]|, cc, distance, hosts_probed);
                	NOTICE([$note=KnockKnockScan, $src=orig,
                                  $src_peer=get_local_event_peer(), $msg=fmt("%s", _msg)]);
			log_reporter (fmt ("NOTICE: FOUND KnockKnockScan: %s", orig),0);

			#### TODO: moved to check_scan_impl: 
			#### Scan::add_to_known_scanners(orig, "KnockKnockScan"); 
		} 
        # # # # # ## # # # # #
	return result ; 
} 


#check_knockknock_scan: 222.85.138.75, 3128/tcp, 131.243.192.47, 1463019177.63643, 1463019216.164206 - DETECTED
#1463019177.636430 error in ./.././check-knock.bro, line 199: value used but not set (Scan::add_to_known_scanners)
#1463019177.636430 error in ./.././check-knock.bro, line 250: no such index (Scan::known_scanners[Scan::orig])
#1463019177.636430 error in ./.././check-knock.bro, line 251: no such index (Scan::known_scanners[Scan::orig])


function check_KnockKnockScan(cid: conn_id, established: bool, reverse: bool ): bool 
{
	if (gather_statistics)	
		s_counters$c_knock_checkscan += 1; 

	## already validated connection 

	local orig = cid$orig_h ;
	local resp = cid$resp_h ;
	local d_port = cid$resp_p; 
	
	#already identified as scanner no need to proceed further 
	if (orig in Scan::known_scanners && Scan::known_scanners[orig]$status)
		return F;

	# only worry about TCP connections
        # we deal with udp and icmp scanners differently
        
	if (get_port_transport_proto(cid$resp_p) != tcp)
                         return F;

	######## memory optimizations 
	if (enable_big_tables) 
	{ 
		if ([orig,d_port] !in likely_scanner)
		{ 
			likely_scanner[orig,d_port]=set(); 
		} 

		if (resp !in likely_scanner[orig,d_port])
		{ 
			add likely_scanner[orig,d_port][resp];
		} 
	} 


	if ([orig, d_port] !in c_likely_scanner)
	{
		local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99); 
		c_likely_scanner[orig,d_port]=cp  ; 
	} 
	
	hll_cardinality_add(c_likely_scanner[orig,d_port], resp);	

	local result = check_knockknock_scan(orig, d_port, resp); 

	#### TODO: this should go down further into check-scan-impl.bro code 
	if (result) 
	{ 
		# Important want ot make sure we update the detect_ts to nearest time of occurence 
		###Scan::known_scanners[orig]$detect_ts = network_time(); 
		####log_reporter(fmt("knockknock scanner detected at %s, %s on %s", orig, Scan::known_scanners[orig]$detect_ts, peer_description),0); 
	
		return T ; 
	} 

return F ; 

}


####### clusterizations 

event udp_request(u: connection )
{
}

event udp_reply (u: connection )
{

}

function get_haversine_distance(orig: addr, resp: addr): double 
{
	local distance = 0.0 ;
	
	local orig_loc = lookup_location(orig);
       	local resp_loc = lookup_location(resp);

        #if (orig_loc?$latitude &&  orig_loc?$longitude &&  resp_loc?$latitude && resp_loc?$longitude)
        #        { distance = haversine_distance(orig_loc$latitude, orig_loc$longitude, resp_loc$latitude, resp_loc$longitude);}

	return distance ; 
}
	

@if (! Cluster::is_enabled())
event connection_state_remove(c: connection) 
{
	local darknet = F; 
####	check_KnockKnockScan(c$id, F, F) ; 
}
@endif 

function validate_KnockKnockScan(c: connection, darknet: bool ): string 
{ 


	if (gather_statistics)	
		s_counters$c_knock_validate += 1; 

	if (! activate_KnockKnockScan)
		return ""; 

        local orig = c$id$orig_h ;
        local resp = c$id$resp_h ;
        local d_port = c$id$resp_p ;
	local s_port = c$id$orig_p ; 
	
	# internal host scanning handled seperately 
        if (Site::is_local_addr(c$id$orig_h))
                return "";

	###local darknet = Scan::is_darknet(c$id$resp_h); 

	if (! darknet ) 
	{ 
		# only worry about TCP connections 	
		# we deal with udp and icmp scanners differently 
	        if (get_port_transport_proto(c$id$resp_p) != tcp)
       		         return "";

		# a) full established conns not interesting 
		if (c$resp$state == TCP_ESTABLISHED) 
		{ return ""; } 

		# b) full established conns not interesting 
		if (c?$conn && c$conn?$conn_state ) 
		{ 
			if (/SF/ in c$conn$conn_state) 
				{	return "";  } 
		
			local state = c$conn$conn_state ; 
			local resp_bytes =c$resp$size ; 
			
			# mid stream traffic - ignore  
			if (state == "OTH" &&  resp_bytes >0 )
			{	return ""; } 
		} 

	} 
	
	# ignore traffic to host/port  this is primarily whitelisting 
	# maintained in ipportexclude_file for sticky config firewalled hosts 
	if ([resp, d_port] in ipportexclude) 
	{	return "";  } 

	# if ever a SF a LBL host on this port - ignore the orig completely 
	if (resp in Site::host_profiles && d_port in Site::host_profiles[resp])
		return ""; 

	# don't need to process known_scanners again 	
	if (orig in Scan::known_scanners && Scan::known_scanners[orig]$status) 
	{ 
		log_reporter(fmt("check_KnockKnockScan: orig in known_scanner"),0); 
		return ""; 
	} 

	# finally a scan candidate 	
	return "K"  ; 
	#add_to_knockknock_cache(orig, d_port, resp); 

}


event bro_init()
{

Input::add_table([$source=ipportexclude_file, $name="ipportexclude", $idx=ipportexclude_Idx, $val=ipportexclude_Val,  $destination=ipportexclude, $mode=Input::REREAD ]);

} 

