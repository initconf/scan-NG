
module ICMP;

export {

        redef enum Notice::Type += {
                ICMPAsymPayload,        # payload in echo req-resp not the same
                ICMPConnectionPair,     # too many ICMPs between hosts
                ICMPAddressScan,
		TimestampScan, 
		InfoRequestScan, 
		AddressMaskScan, 
		ScanSummary, 

                # The following isn't presently sufficiently useful due
                # to cold start and packet drops.
                # ICMPUnpairedEchoReply,        # no EchoRequest seen for EchoReply
        };

        # Whether to log detailed information icmp.log.
        const log_details = T &redef;

        # ICMP scan detection.
        const detect_scans = T &redef;
        const scan_threshold = 25 &redef;
	const scan_summary_trigger = 25 &redef;

        # Analysis of connection pairs.
        const detect_conn_pairs = F &redef;     # switch for connection pair
        const detect_payload_asym = F &redef;   # switch for echo payload
        const conn_pair_threshold = 200 &redef;

####

        global conn_pair:table[addr] of set[addr] &create_expire = 1 day;
        global conn_pair_thresh_reached: table[addr] of bool &default=F;

	global scan_summary: function(t: table[addr] of set[addr], orig: addr): interval; 

        global distinct_peers: table[addr] of set[addr]
                &read_expire = 1 days  &expire_func=scan_summary &redef;

        global shut_down_thresh_reached: table[addr] of bool &default=F;



        const skip_scan_sources = {
                255.255.255.255,        # who knows why we see these, but we do

                # AltaVista.  Here just as an example of what sort of things
                # you might list.
                #test-scooter.av.pa-x.dec.com,
        } &redef;

         const skip_scan_nets: set[subnet] = {} &redef;
}


function scan_summary(t: table[addr] of set[addr], orig: addr): interval
{
        local num_distinct_peers = orig in t ? |t[orig]| : 0;

        if ( num_distinct_peers >= scan_summary_trigger )
                NOTICE([$note=ScanSummary, $src=orig, $n=num_distinct_peers,
                        $msg=fmt("%s scanned a total of %d hosts",
                                        orig, num_distinct_peers)]);
        return 0 secs;
}


function check_scan(orig: addr, resp: addr):bool
{

	 if ( detect_scans && (orig !in ICMP::distinct_peers || resp !in ICMP::distinct_peers[orig]) )
                {
                if ( orig !in ICMP::distinct_peers )
                        {
                        local empty_peer_set: set[addr] &mergeable;
                        ICMP::distinct_peers[orig] = empty_peer_set;
                        }

                if ( resp !in ICMP::distinct_peers[orig] )
                        add ICMP::distinct_peers[orig][resp];

                if ( ! ICMP::shut_down_thresh_reached[orig] &&
                     orig !in ICMP::skip_scan_sources &&
                     orig !in ICMP::skip_scan_nets &&
                     |ICMP::distinct_peers[orig]| >= scan_threshold )
			return T ;

	} 

	return F ; 


} 

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
        local orig = icmp$orig_h;
        local resp = icmp$resp_h;

	if (check_scan(orig,resp)) 
	{
		NOTICE([$note=ICMPAddressScan, $src=orig,
			$n=scan_threshold,
			$msg=fmt("%s has icmp echo scanned %s hosts",
			orig, scan_threshold)]);

		ICMP::shut_down_thresh_reached[orig] = T;
	} 

        if ( detect_conn_pairs )
                {
                if ( orig !in conn_pair )
                        {
                        local empty_peer_set2: set[addr] &mergeable;
                        conn_pair[orig] = empty_peer_set2;
                        }

                if ( resp !in conn_pair[orig] )
                        add conn_pair[orig][resp];

                if ( ! conn_pair_thresh_reached[orig] &&
                     |conn_pair[orig]| >= conn_pair_threshold )
                        {
                        NOTICE([$note=ICMPConnectionPair,
                                $msg=fmt("ICMP connection threshold exceeded : %s -> %s",
                                orig, resp)]);
                        conn_pair_thresh_reached[orig] = T;
                        }
                }
}




event icmp_sent (c: connection , icmp: icmp_conn )
{

	local orig=c$id$orig_h ; 
	local resp=c$id$resp_h ; 


	if (icmp$itype==13 || icmp$itype == 14) ## timestamp queries 
	{ 
		if (check_scan(orig, resp)) 
		{
	              NOTICE([$note=TimestampScan, $src=orig,
                                $n=scan_threshold,
                                $msg=fmt("%s has icmp timestamp scan %s hosts",
                                orig, scan_threshold)]);

                        ICMP::shut_down_thresh_reached[orig] = T;
		} 
	} 


	if (icmp$itype==15 || icmp$itype == 16 )
	{ 
		if (check_scan(orig, resp))
                {
                      NOTICE([$note=InfoRequestScan, $src=orig,
                                $n=scan_threshold,
                                $msg=fmt("%s has icmp timestamp scan %s hosts",
                                orig, scan_threshold)]);

                        ICMP::shut_down_thresh_reached[orig] = T;
                }
        }

	
        if (icmp$itype==17|| icmp$itype == 18)
        {
                if (check_scan(orig, resp))
                {
                      NOTICE([$note=AddressMaskScan, $src=orig,
                                $n=scan_threshold,
                                $msg=fmt("%s has icmp timestamp scan %s hosts",
                                orig, scan_threshold)]);

                        ICMP::shut_down_thresh_reached[orig] = T;
                }
        }


} 


event bro_done()
        {
        for ( orig in distinct_peers )
                scan_summary(distinct_peers, orig);

}


event icmp_sent_payload (c: connection , icmp: icmp_conn , payload: string )
{

        #print fmt ("%s: PAYLoad: %s", icmp, payload);

}
