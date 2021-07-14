module Scan; 

export {

	const activate_LowPortTrolling = T &redef;

	# Ignore address scanners for further scan detection after
        # scanning this many hosts.
        # 0 disables.
        #const ignore_scanners_threshold = 0 &redef;


         redef enum Notice::Type += {
		LowPortTrolling,        # source touched privileged ports
                LowPortScanSummary,     # summary of distinct low ports per scanner
        };

        global lowport_summary:
                function(t: table[addr] of set[port], orig: addr): interval;
	global distinct_low_ports: table[addr] of set[port]
		&read_expire = 1 days  &expire_func=lowport_summary &redef;

        const lowport_summary_trigger = 10 &redef;


	# Threshold for scanning privileged ports.
	const priv_scan_trigger = 5 &redef;
	const troll_skip_service = {
		25/tcp, 21/tcp, 22/tcp, 20/tcp, 80/tcp, 443/tcp, 
	} &redef;

	global filterate_LowPortTroll: function(c: connection, established: bool, reverse: bool): string ; 

}

function lowport_summary(t: table[addr] of set[port], orig: addr): interval
        {
        local num_distinct_lowports = orig in t ? |t[orig]| : 0;

        if ( num_distinct_lowports >= lowport_summary_trigger )
                NOTICE([$note=LowPortScanSummary, $src=orig,
                        $n=num_distinct_lowports,
                        $msg=fmt("%s scanned a total of %d low ports",
                                        orig, num_distinct_lowports)]);

        return 0 secs;
        }


	#orig: addr, service: port, resp: addr): bool 
function check_LowPortTroll(cid: conn_id, established: bool, reverse: bool): bool 
{
	local id = cid;

        local service = reverse ? id$orig_p : id$resp_p;
        local rev_service = reverse ? id$resp_p : id$orig_p;
        local orig = reverse ? id$resp_h : id$orig_h;
        local resp = reverse ? id$orig_h : id$resp_h;
        local outbound = Site::is_local_addr(orig);


	local troll = F ;
	if ( orig !in distinct_low_ports ||
	     service !in distinct_low_ports[orig] )
		{
		if ( orig !in distinct_low_ports )
			distinct_low_ports[orig] = set() ;

		add distinct_low_ports[orig][service];

		if ( |distinct_low_ports[orig]| == priv_scan_trigger &&
		     orig !in Site::neighbor_nets )
			{
			#local s = service in port_names ? port_names[service] : fmt("%s", service);
			local s = fmt("%s", service);


			local svrc_msg = fmt("low port trolling %s %s", orig, s);
			NOTICE([$note=LowPortTrolling, $src=orig,
				$p=service, 
				$p=service, $msg=svrc_msg]);

			troll = T ; 
			}

		} 

	return troll; 
} 

function filterate_LowPortTroll(c: connection, established: bool, reverse: bool): string 
{
	if ( established )
	{
		# Don't consider established connections for port scanning,
		# it's too easy to be mislead by FTP-like applications that
		# legitimately gobble their way through the port space.
		return "" ; 
	}

	local id = c$id;

	local service = "ftp-data" in c$service ? 20/tcp
			: (reverse ? id$orig_p : id$resp_p);
	local rev_service = reverse ? id$resp_p : id$orig_p;
	local orig = reverse ? id$resp_h : id$orig_h;
	local resp = reverse ? id$orig_h : id$resp_h;
	local outbound = Site::is_local_addr(orig);
	
	if (orig in Scan::known_scanners && Scan::known_scanners[orig]$status) 
		return "" ; 
		     
	if (orig in Site::neighbor_nets )
		return "" ; 

	# Check for low ports.
	if ( activate_LowPortTrolling && ! outbound && service < 1024/tcp &&
	     service !in troll_skip_service )
	{
		return "T" ; 
		# local troll_result = check_lowporttrolling(orig, service, resp); 
	}

	return "" ; 
} 



# events for scan detections

#event connection_established(c: connection)
#        {
#        local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#        Scan::check_LowPortTroll(c, T, is_reverse_scan);
#
#        #local trans = get_port_transport_proto(c$id$orig_p);
#        #if ( trans == tcp && ! is_reverse_scan && TRW::use_TRW_algorithm )
#        #       TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event partial_connection(c: connection)
#        {
#        Scan::check_LowPortTroll(c, T, F);
#        }
#
#event connection_attempt(c: connection)
#        {
#    local is_reverse_scan = (c$orig$state == TCP_INACTIVE && c$id$resp_p !in likely_server_ports);
#        Scan::check_LowPortTroll(c, F, is_reverse_scan);
#
#        #local trans = get_port_transport_proto(c$id$orig_p);
#        #if ( trans == tcp && TRW::use_TRW_algorithm )
#        #       TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event connection_half_finished(c: connection)
#        {
#        # Half connections never were "established", so do scan-checking here.
#        Scan::check_LowPortTroll(c, F, F);
#        }
#
#event connection_rejected(c: connection)
#        {
#        local is_reverse_scan = (c$orig$state == TCP_RESET && c$id$resp_p !in likely_server_ports);
#
#        Scan::check_LowPortTroll(c, F, is_reverse_scan);
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
#                Scan::check_LowPortTroll(c, c$orig$size + c$resp$size > 0, is_reverse_scan);
#        }
#        }
#
#event connection_pending(c: connection)
#        {
#        if ( c$orig$state == TCP_PARTIAL && c$resp$state == TCP_INACTIVE )
#                Scan::check_LowPortTroll(c, F, F);
#        }
#
#
