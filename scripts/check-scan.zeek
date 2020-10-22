### this is the core module which integrates and enables and disables 
### all the scan-detection suite 

module Scan;

export { 
	
global check_scan: function (c: connection, established: bool, reverse: bool); 



#global not_scanner: function (cid: conn_id): bool ; 

} 

global uid_table: table[string] of bool &default=F &create_expire=5 mins ;

event zeek_init()
{ 
	event table_sizes() ; 
}	


## Checks if an IP qualies the criteria of being a NOT scanner 
## 
## cid: connection record 
##
## Returns: bool - T/F depending on various conditions satisfied internally 
function not_scanner(cid: conn_id): bool 
{
	local orig = cid$orig_h ; 
	local orig_p = cid$orig_p ; 
	local resp = cid$resp_h ; 
	local service = cid$resp_p ; 
	local outbound = Site::is_local_addr(orig);

#@ifdef (NetControl::BlockInfo)
#	if (is_catch_release_active(cid) )
#	{ 
#		if (orig in known_scanners && cid$resp_p in Scan::skip_services)
#		{ 
#			local code: bool = F ; 
#			code = NetControl::unblock_address_catch_release(cid$orig_h, "tcpsynportblock: Removing IP from catch-n-release"); 
#			NOTICE([$note=DisableCatchRelease, $src=orig, $p=service, $id=cid, $src_peer=get_local_event_peer(), $msg=fmt ("Disable catch-n-release because %s added to skip_services", resp)]);
#			#log_reporter(fmt("unblock_address_catch_release: %s, %s", cid$orig_h, code), 10); 
#		} 
#
#		return T ; 
#	} 
#@endif 

	local result = F ; 
	
	# blocked_nets - we don't want to put this here
	# since this means we ignore and not see 
	# scanners from blocked nets anymore 
	# moving this to post scan-detection ie populate_known_scanners
	#if (orig in blocked_nets) 
	#	return T ;

        # whitelist membership checks
        if (orig in Scan::whitelist_ip_table)
                return T ;

        if (orig in Scan::whitelist_subnet_table)
                return T ;
	
	# ignore scan sources 
	if (orig in skip_scan_sources)
	{       return  T ; }

	if (orig_p == 7547/tcp  )
	{ 	return T; } 
	
	#if (orig_p in skip_services && orig_p == 7547/tcp  )
	#{ 	return T ; } 

	#if ( service in skip_services &&  ! outbound )
	#	return T;
	
	if ( outbound && service in skip_outbound_services )
		return T;
	
	if ( orig in skip_scan_nets )
		return T;
	
	# Don't include well known server/ports for scanning purposes.
	if ( ! outbound && [resp, service] in skip_dest_server_ports )
		return T;
	
	# check for conn_history - that is if we ever saw a full SF going to this IP
	#f (History::check_conn_history(orig))
	#	return T ; 

	# enabling udp for Landmine - aashish 2019-09-16 
	# we only deal with tcp scanners and icmp for now
	# Enabling UDP on LandMine -2019-09-16 aashish 
	#if (service >= 0/udp && service <= 65535/udp) 
	#	return T; 

	# ignore traffic to host/port  this is primarily whitelisting
        # maintained in knock_exceptions_file for sticky config firewalled hosts
        if (resp in Site::local_nets && [resp, service] in knock_exceptions)
        {       return T;  }


	return result ; 
} 

## Primary entry point of :bro:see:`Scan::check_scan` modoule 
## It is called by :bro:see:`new_connection`, :bro:see:`connection_state_remove`, :bro:see:`connection_established`
## :bro:see:`connection_attempt`, :bro:see:`connection_rejected`, :bro:see:`partial_connection`, :bro:see:`connection_half_finished`, 
## :bro:see:`connection_reset`, :bro:see:`connection_pending` events
## 
## c: connection_record :see:bro:`connection` 
## 
## established: bool - if a connection between endpoints is established 
##
## reverse: bool - if connection is from setup from destination to source instead 
function check_scan(c: connection, established: bool, reverse: bool)
{

	local orig=c$id$orig_h ; 

	### already a known_scanner 
	if (orig in Scan::known_scanners && Scan::known_scanners[orig]$status) 
	{ 
		if (gather_statistics)
                        s_counters$already_scanner_counter += 1;
		return ; 
	} 



	if (not_scanner(c$id))
	{ 
		if (gather_statistics)
                        s_counters$not_scanner += 1;
		return ; 
	} 

	#log_reporter(fmt ("check_scan: scanner: orig in known_scanners for %s", c$id$orig_h),10);


       	local resp = c$id$resp_h ;

	### if darknet then fast-pace the detection for landmine, knockknoc and
	### backscatter so that we don't ahve to wait till tcp_attempt_delay expiration 
	### of 5 sec 

	local darknet = F ; 

        if (Site::is_local_addr(resp) && resp !in Site::subnet_table)
        {
		darknet = T ; 

		#print fmt ("DARKNET: %s, %s", c$uid, c$id);
	 	if (gather_statistics)
                        s_counters$darknet_counter += 1;

	} 
        ### only watch for live subnets - since conn_state_remove adds
        ### 5.0 sec of latency to tcp_attempt_delay
        ### Unsuccessful is defined as at least tcp_attempt_delay seconds
        ### having elapsed since the originator first sent a connection
        ### establishment packet to the destination without seeing a reply.

	else if (Site::is_local_addr(resp) && resp in Site::subnet_table)
	{ 
	 	if (gather_statistics)
                        s_counters$not_darknet_counter += 1;
		darknet = F ; 
	} 


	local filter__Backscatter = "" ;
	local filter__KnockKnock = "" ;
	local filter__LandMine = "" ;
	local filter__AddressScan = "" ;
	local filter__PortScan = "" ;
	local filter_port_knock = "" ; 
	local filter__LowPortTroll = "" ; 
	
        
	# run filteration code on the workers for each scan module 
	# if a connectiond doesn't fit what is eventually one of the criterias of a 
	# detection heuristic, filteration for that heuristic is a F 
	# only connections with T filteration are processed further to be analyzed 

	# (ii) we check against uid_table[c$uid] because if conn is already sent to manager
	# based on earlier event (eg. conn_attempt) we save extra processing for subsiquent
	# events (eg. conn_state_remove) 

	# only check landmine if darknet ip 
	if (activate_LandMine && ! uid_table[c$uid] && darknet )
			filter__LandMine = Scan::filterate_LandMineScan(c, darknet ); 
	if (activate_BackscatterSeen && ! uid_table[c$uid])
		filter__Backscatter = Scan::filterate_BackscatterSeen(c, darknet);

	if (activate_KnockKnockScan && ! uid_table[c$uid])
			filter__KnockKnock = Scan::filterate_KnockKnockScan(c, darknet); 

	if (activate_AddressScan && ! uid_table[c$uid])
		filter__AddressScan = Scan::filterate_AddressScan(c, established, reverse); 
	
	if (activate_LowPortTrolling && ! uid_table[c$uid] )
		filter__LowPortTroll = Scan::filterate_LowPortTroll(c, established, reverse); 


	# we hold off on PortScan to use the heuristics provided by sumstats 	
	# if (activate_PortScan)
  	#	filter__PortScan = Scan::filterate_PortScan(c, established, reverse) ; 


	if (/K/ in filter__KnockKnock || /L/ in filter__LandMine || /B/ in filter__Backscatter  || /A/ in filter__AddressScan || /T/ in filter__LowPortTroll)  
	{ 
		#### So connection met one or more of heuristic filteration criterias 
		#### send for further determination into check-scan-impl.bro now 
	
		if (gather_statistics)
			s_counters$filteration_success += 1;

		### we maintain a uid_table with create_expire of 30 secs so that same connection processed by one event 
		### is not again sent - for example if C is already processed in scan-engine for new_connection, lets not 
		### process same C for subsiquent TCP events such as conn_terminate or conn_rejected etc. 
		if (c$uid !in uid_table)
		{ 
			local filterator = fmt("%s%s%s%s%s%s", filter__KnockKnock, filter__LandMine, filter__Backscatter, filter__AddressScan, filter__PortScan,filter__LowPortTroll); 
			uid_table[c$uid]=T ; 
			check_scan_cache(c, established, reverse, filterator) ; 
			add scan_candidates[c$id$orig_h] ; 
		} 
	} 
} 


### speed up landmine and knockknock for darknet space 
event new_connection(c: connection)
{
	#print fmt ("new_connection"); 
	### for new connections we just want to supply C and only for darknet spaces 
	### to speed up reaction time and to avoind tcp_expire_delays of 5.0 sec  

	# only external IPs 
	if (c$id$orig_h in Site::local_nets)
		return ; 

	# don't process known_scanners 
	if (c$id$orig_h in Scan::known_scanners)
		return ; 

	#print fmt ("c$id$orig_h: %s, known_scanners: %s, counters: %s ", c$id$orig_h, known_scanners, s_counters); 

	if (gather_statistics)
	{ 
		s_counters$event_peer = fmt ("%s", peer_description); 
		s_counters$new_conn_counter += 1; 
	} 

         local tp = get_port_transport_proto(c$id$resp_p);
        
	if (tp == tcp && c$id$orig_h !in Site::local_nets && is_darknet(c$id$resp_h) )
	{
		Scan::check_scan(c, F, F); 
	} 
} 

event connection_state_remove(c: connection)
{

	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

	local id = c$id ;
        local service =  id$resp_p ;

	local trans = get_port_transport_proto(service);

        # don't operate on a connection which responder
        # sends data back in a udp connection ie c$history = d

        if (  ((trans == udp) && (/d/ !in c$history)) || trans == tcp || trans == icmp ) 
        {
		check_scan(c, F, F); 
	} 
}


event connection_established(c: connection)
       {


	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

	#print fmt("connection_established"); 

       local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
       Scan::check_scan(c, T, is_reverse_scan);

       local trans = get_port_transport_proto(c$id$orig_p);
       if ( trans == tcp && ! is_reverse_scan && TRW::use_TRW_algorithm )
              TRW::check_TRW_scan(c, conn_state(c, trans), F);
       }

event partial_connection(c: connection)
       {
	#print fmt("partial_connection"); 

	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

       Scan::check_scan(c, T, F);
       }

event connection_attempt(c: connection)
       {
	#print fmt("connection_attempt"); 

	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

	local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
       	Scan::check_scan(c, F, is_reverse_scan);

       local trans = get_port_transport_proto(c$id$orig_p);
       if ( trans == tcp && TRW::use_TRW_algorithm )
              TRW::check_TRW_scan(c, conn_state(c, trans), F);
       }

event connection_half_finished(c: connection)
       {

	#print fmt ("conn_half_finished"); 
	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

       # Half connections never were "established", so do scan-checking here.
       Scan::check_scan(c, F, F);
       }

event connection_rejected(c: connection)
       {

	#print fmt("conn_rejected"); 

	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

       local is_reverse_scan = (c$orig$state == TCP_RESET && c$id$resp_p !in likely_server_ports);

       Scan::check_scan(c, F, is_reverse_scan);

       local trans = get_port_transport_proto(c$id$orig_p);
       if ( trans == tcp && TRW::use_TRW_algorithm )
              TRW::check_TRW_scan(c, conn_state(c, trans), is_reverse_scan);
       }

event connection_reset(c: connection)
       {

	#print fmt("conn_reset"); 

	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

       if ( c$orig$state == TCP_INACTIVE || c$resp$state == TCP_INACTIVE )
        {
        local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
               # We never heard from one side - that looks like a scan.
               Scan::check_scan(c, c$orig$size + c$resp$size > 0, is_reverse_scan);
        }
       }

event connection_pending(c: connection)
       {
	
	#print fmt ("conn_pending") ; 

	# only external IPs
        if (c$id$orig_h in Site::local_nets)
                return ;

        # don't process known_scanners
        if (c$id$orig_h in Scan::known_scanners)
                return ;

       if ( c$orig$state == TCP_PARTIAL && c$resp$state == TCP_INACTIVE )
               Scan::check_scan(c, F, F);
       }


#### no need of these ############ TRW Events 
#
#
#event connection_established(c: connection)
#{
#	local is_reverse_scan = (c$orig$state == TCP_INACTIVE);
#	local trans = get_port_transport_proto(c$id$orig_p);
#
#	if ( trans == tcp && ! is_reverse_scan && TRW::use_TRW_algorithm )
#		TRW::check_TRW_scan(c, conn_state(c, trans), F);
#}
#
#event connection_attempt(c: connection)
#{
#        local trans = get_port_transport_proto(c$id$orig_p);
#        if ( trans == tcp && TRW::use_TRW_algorithm )
#                TRW::check_TRW_scan(c, conn_state(c, trans), F);
#}
#
#event connection_rejected(c: connection)
#{
#        local is_reverse_scan = c$orig$state == TCP_RESET;
#
#        local trans = get_port_transport_proto(c$id$orig_p);
#        if ( trans == tcp && TRW::use_TRW_algorithm )
#                TRW::check_TRW_scan(c, conn_state(c, trans), is_reverse_scan);
#}
############

