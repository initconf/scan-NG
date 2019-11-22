### policy to determine backscatter traffic which is mainly charaterized by:
### No Syn seen from Originator but only syn-ack, or Fin seen 
### Backscatter is primarily result of someone spoofing LBL address space to participate 
### in a DoS.
### use of this policy is so that we needlessly don't block a victim IP 
### intention of this policy is to mostly provide scan-detection an advice about backscatter status

#### heuristics also include observation that a backscatter which is result of DoS generally 
### is limited to only a few selected ports 
### so we count how many uniq src ports are seen. IF > BackscatterThreshold, we ignore the 
### remaining traffic

module Scan;

export {

	#const DEBUG = 1; 
	global activate_BackscatterSeen = T &redef ; 

	
        redef enum Notice::Type += {
                BackscatterSeen,
	} ; 

	# Reverse (SYN-ack) scans seen from these ports are considered
        # to reflect possible SYN-flooding backscatter, and not true
        # (stealth) scans.
        const backscatter_ports:set[port] = {} &redef;
        const report_backscatter: vector of count = {} &redef;

	global backscatter: table[addr] of count &create_expire=1 day; 
	global distinct_backscatter_peers: table[addr] of table[port] of set[addr] &read_expire=1 day; 

	type bs: table[port] of opaque of cardinality &default=function(p:port): opaque of cardinality {return hll_cardinality_init(0.1, 0.99); };
        global c_distinct_backscatter_peers: table[addr] of bs  &create_expire=1 day ;

	# backscatter traffic doesn't generally have > 10 uniq src port 
	# also to prevent the table from bloating up 
	const BACKSCATTER_PORT_THRESH = 2 ; 
	const BACKSCATTER_THRESH = 10 ; 
	
	global check_BackscatterSeen: function(cid: conn_id, established: bool, reverse: bool): bool ; 
	global filterate_BackscatterSeen: function (c: connection, darknet: bool ): string  ; 
}


function c_check_backscatter_thresholds(orig: addr, s_port: port, resp: addr): bool
{

	 if (gather_statistics)
                s_counters$c_backscat_core += 1  ;

        local result = F;

        if ( orig !in c_distinct_backscatter_peers)
                c_distinct_backscatter_peers[orig] = table() ;

        if (|c_distinct_backscatter_peers[orig]| > BACKSCATTER_PORT_THRESH)
        { return F ; }

         # track upto 2 uniq src port
        if (|c_distinct_backscatter_peers[orig]| <= BACKSCATTER_PORT_THRESH)
        {
                if (s_port !in c_distinct_backscatter_peers[orig])
                {
                        local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99);
                        c_distinct_backscatter_peers[orig][s_port]=cp ;
                }

                hll_cardinality_add(c_distinct_backscatter_peers[orig][s_port], resp);

                local d_val = double_to_count(hll_cardinality_estimate(c_distinct_backscatter_peers[orig][s_port]));

                        if (d_val >= BACKSCATTER_THRESH)
                        {
                                #print fmt("CARDINAL: backscatter seen from %s (%d port: %s)", orig, |distinct_backscatter_peers[orig]|, s_port) ;
				NOTICE([$note=BackscatterSeen, $src=orig,
                                                $p=s_port,
                                                $msg=fmt("backscatter seen from %s (%d port: %s)",
                                                        orig, d_val, s_port)]);

                                ## is a scanner now
                                result = T ;
                        }
        }

        return result ;

}



function check_backscatter_thresholds(orig: addr, rev_svc: port, resp: addr): bool 
{ 

	 if (gather_statistics)
                s_counters$c_backscat_core += 1  ;

	local result = F; 
	
        if ( orig !in distinct_backscatter_peers)
                distinct_backscatter_peers[orig] = table() &mergeable;

	if (|distinct_backscatter_peers[orig]| > BACKSCATTER_PORT_THRESH)
	{ return F ; } 

		

	 # track upto 2 uniq src port
        if (|distinct_backscatter_peers[orig]| <= BACKSCATTER_PORT_THRESH)
        {
		if (rev_svc !in distinct_backscatter_peers[orig]) 
			distinct_backscatter_peers[orig][rev_svc] = set() &mergeable;

                if ( resp !in distinct_backscatter_peers[orig][rev_svc] )
                {
                        add distinct_backscatter_peers[orig][rev_svc][resp];

                        if (|distinct_backscatter_peers[orig][rev_svc][resp]| >= BACKSCATTER_THRESH)
                        {
                                NOTICE([$note=BackscatterSeen, $src=orig,
                                                $p=rev_svc, 
                                                $msg=fmt("backscatter seen from %s (%d port: %s)",
                                                        orig, |distinct_backscatter_peers[orig]|, rev_svc)]);
				## is a scanner now 
				result = T ; 
				log_reporter (fmt ("NOTICE: FOUND BackscatterSeen : %s, result : %s", orig, result),0);
                        }
                }
	} 


	return result ; 

} 

function check_BackscatterSeen(cid: conn_id, established: bool, reverse: bool): bool 
{

	 if (gather_statistics)
                s_counters$c_backscat_checkscan += 1  ;


        local orig = cid$orig_h ;
        local resp = cid$resp_h ;
        local d_port = cid$resp_p ;
        local rev_svc = cid$orig_p ;

	#already identified as scanner no need to proceed further
        if (orig in Scan::known_scanners && Scan::known_scanners[orig]$status)
	{ 
		### log_reporter(fmt("in check_BackscatterSeen: known_scanner: %s", known_scanners[orig]),0);
                return F;
	} 

	if (orig in backscatter)
		return F ; 

	local c_result = c_check_backscatter_thresholds(orig, rev_svc, resp); 

	if (enable_big_tables)
	{ 
		local result = check_backscatter_thresholds(orig, rev_svc, resp); 
	} 


	#log_reporter(fmt("in check_BackscatterSeen log result is : %s for %s", result, cid),0); 

	if (c_result)
	{ 
		#log_reporter(fmt("in check_BackscatterSeen log result II is : %s for %s", result, cid),0); 
		#add_to_known_scanners(orig, "BackscatterScan");
		backscatter[orig] = 1 ; 
	} 
	
	return c_result ;  
}


#[id=[orig_h=167.114.206.157, orig_p=9010/tcp, resp_h=128.3.64.182, resp_p=49003/tcp], 
#orig=[size=0, state=6, num_pkts=2, num_bytes_ip=80, flow_label=0], 
#resp=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0], 
#start_time=1456189676.188253, 
#duration=0.000003, 
#service={\x0a\x0a}, 
#history=R, 
#uid=CqjpWA43cXknfcEVIh, 
#conn=[ts=1456189676.188253, uid=CqjpWA43cXknfcEVIh, id=[orig_h=167.114.206.157, orig_p=9010/tcp, resp_h=128.3.64.182, resp_p=49003/tcp], proto=tcp, service=<uninitialized>, duration=0.000003, orig_bytes=0, resp_bytes=0, conn_state=RSTOS0, local_orig=<uninitialized>, local_resp=<uninitialized>, missed_bytes=0, history=R, orig_pkts=2, orig_ip_bytes=80, resp_pkts=0, resp_ip_bytes=0, 
#



function filterate_BackscatterSeen(c: connection, darknet: bool ): string  
{

        if (! activate_BackscatterSeen)
                return "";

	 if (gather_statistics)
                s_counters$c_backscat_filterate += 1  ;

        local orig = c$id$orig_h ;
        local resp = c$id$resp_h ;
        local d_port = c$id$resp_p ;
        local s_port = c$id$orig_p ;

        if (get_port_transport_proto(c$id$resp_p) != tcp)
                return "";

        # internal host scanning handled seperately
        if (Site::is_local_addr(c$id$orig_h))
                return "";

	if (! darknet) 
	{ 

		# only worry about TCP connections
		# we deal with udp and icmp scanners differently

		# Blocked on border router - perma firewalled
		#if (d_port in ignore_already_blocked_ports)
		#        return "";

		# a) full established conns not interesting
		if (c$resp$state == TCP_ESTABLISHED)
		{ return ""; }

		# b) full established conns not interesting
		if (c?$conn &&  c$conn?$conn_state && /SF/ in c$conn$conn_state)
		{       return "";  }

		local state = "" ; 
		if (c?$conn && c$conn?$conn_state)
			state = c$conn$conn_state ; 

		local resp_bytes =c$resp$size ;

		# mid stream traffic - ignore
		if (state == "OTH" &&  resp_bytes >0 )
		{       return ""; }
		
		
		} 

		#print fmt ("ORIG: %s", print_state(c$orig$state, c$conn$proto)); 
		#print fmt ("RESP: %s", print_state(c$resp$state, c$conn$proto)); 

		#### tmp if (state == "REJ" &&  resp_bytes >0 )
		#	{ print fmt ("REJ + Bytes: %s", c$id);  }

		#if (state == "RSTR" &&  resp_bytes >0 )
		#{       print fmt ("RSTR + Bytes: %s", c$id);  }
		
		# 
		#if (state == "OTH" &&  resp_bytes == 0 )
		#{       print fmt ("OTH + 0 resp_bytes: %s", c$id);  } 

		
		if ((c$orig$state == TCP_SYN_ACK_SENT && c$resp$state == TCP_INACTIVE) || 
		(c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_INACTIVE) ||
		(c$history == "F" || c$history == "R" )  || 
		(c$history == "H" && /s|a/ !in c$history ) ) 
		{ 
			####if (check_BackscatterSeen(c$id, F, F))
			return "B" ;
		} 

	### 2016-05-23 we dont want to run backscatter on workers 
	#else 
	#	{
	#	#### enable to run checks locally on workers 
	#	### check_BackscatterSeen(c$id, F, F) ; 
	#	###return "B" ; 
	#	} 


	return "" ;

} 


#@if (! Cluster::is_enabled()) 
#event connection_state_remove(c: connection)
#{
#        check_BackscatterSeen(c) ;
#}
#@endif 


#event connection_established(c: connection)
#	{
#	local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#	Scan::check_scan(c, T, is_reverse_scan);
#
#	#local trans = get_port_transport_proto(c$id$orig_p);
#	#if ( trans == tcp && ! is_reverse_scan && TRW::use_TRW_algorithm )
#	#	TRW::check_TRW_scan(c, conn_state(c, trans), F);
#	}

#event partial_connection(c: connection)
#	{
#	Scan::check_scan(c, T, F);
#	}
#
#event connection_attempt(c: connection)
#	{
#    local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#	Scan::check_scan(c, F, is_reverse_scan);
#
#	#local trans = get_port_transport_proto(c$id$orig_p);
#	#if ( trans == tcp && TRW::use_TRW_algorithm )
#	#	TRW::check_TRW_scan(c, conn_state(c, trans), F);
#	}
#
#event connection_half_finished(c: connection)
#	{
#	# Half connections never were "established", so do scan-checking here.
#	Scan::check_scan(c, F, F);
#	}
#
#event connection_rejected(c: connection)
#	{
#	local is_reverse_scan = (c$orig$state == TCP_RESET && c$id$resp_p !in likely_server_ports);
#
#	Scan::check_scan(c, F, is_reverse_scan);
#
#	#local trans = get_port_transport_proto(c$id$orig_p);
#	#if ( trans == tcp && TRW::use_TRW_algorithm )
#	#	TRW::check_TRW_scan(c, conn_state(c, trans), is_reverse_scan);
#	}
#
#event connection_reset(c: connection)
#	{
#	if ( c$orig$state == TCP_INACTIVE || c$resp$state == TCP_INACTIVE )
#        {
#        local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#		# We never heard from one side - that looks like a scan.
#		Scan::check_scan(c, c$orig$size + c$resp$size > 0, is_reverse_scan);
#        }
#	}
#
#event connection_pending(c: connection)
#	{
#	if ( c$orig$state == TCP_PARTIAL && c$resp$state == TCP_INACTIVE )
#		Scan::check_scan(c, F, F);
#	}
