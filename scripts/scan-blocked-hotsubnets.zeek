module Scan ; 

#redef exit_only_after_terminate = T ; 

export {

	redef enum Notice::Type += {
		HotSubnet,      # Too many scanners originating from this subnet
                BlocknetsIP, 
		BlocknetsFileReadFail,
	}; 


	# /YURTT/feeds/BRO-feeds/WIRED.blocknet 
	# header info 
	#fields NETWORK    BLOCK_FLAVOR
	#2.187.44.0/24   blocknet
	#2.187.45.0/24   blocknet

	type blocknet_Idx: record {
		NETWORK: subnet; 
	};

	type blocknet_Val: record {
		NETWORK: subnet; 
		BLOCK_FLAVOR: string &optional ;
	};

	global blocked_nets: table[subnet] of blocknet_Val = table() &redef ; 
	global blocknet_feed="/YURT/feeds/BRO-feeds/WIRED.blocknet" &redef ; 
} 


export {

	global hot_subnets: table[subnet] of set[addr] &create_expire=7 days;
        global hot_subnets_idx: table[subnet] of count &create_expire=7 days;
        global hot_subnets_threshold: vector of count = { 3, 10, 25, 100, 200, 255 } ;

        global hot_subnet_check:function(ip: addr);
        global check_subnet_threshold: function (v: vector of count, idx: table[subnet] of count, orig: subnet, n: count):bool ;
} 


#### FAILURE-CHECK 
### we catch the error in subnet feed is empty and populate blocked_nets with local_nets 
### so that LandMine detection doesn't block accidently 


hook Notice::policy(n: Notice::Info)
{
        if ( n$note == Scan::BlocknetsFileReadFail) 
        {
            add n$actions[Notice::ACTION_EMAIL];
        }
}

# handle this failure 
# Reporter::WARNING  /YURT/feeds/BRO-feeds/WIRED.blocknet.2/Input::READER_ASCII: 
#	Init: cannot open /YURT/feeds/BRO-feeds/WIRED.blocknet.2    (empty)

event reporter_warning(t: time , msg: string , location: string )
{

        if (/WIRED.blocknet.*\/Input::READER_ASCII: Init: cannot open/ in msg)
	{ 
		NOTICE([$note=BlocknetsFileReadFail, $msg=fmt("%s", msg)]);
	} 
}


event Input::end_of_data(name: string, source: string)                                                         
{                                                                         
	
	if (/WIRED.blocknet/ in name) 
	{ 
		print fmt ("name is %s source is %s", name, source); 
		print fmt("digested  %s records in %s",|source|, source);
	} 
	# since subnet table is zero size
       	# we poulate with local_nets
	
	if (|Scan::blocked_nets| == 0)
	{       
		for (nets in Site::local_nets)
                {       local sv: blocknet_Val ;
                        blocked_nets[nets] = sv ;
               	 }
	} 
} 

event line(description: Input::TableDescription, tpe: Input::Event, left: blocknet_Idx, right: blocknet_Val)
{
        local msg: string;

        if ( tpe == Input::EVENT_NEW ) {
                #print fmt ("NEW");
        }


        if (tpe == Input::EVENT_CHANGED) {
               #print fmt ("CHANGED");
        }


        if (tpe == Input::EVENT_REMOVED ) {
		#print fmt ("REMOVED");

        }
}


event zeek_init() &priority=10
{
        Input::add_table([$source=blocknet_feed, $name="blocked_nets", $idx=blocknet_Idx, $val=blocknet_Val,  $destination=blocked_nets, $mode=Input::REREAD, $ev=line]);  
        

 ####     Input::add_table([$source=blocknet_feed, $name="blocked_nets", $idx=blocknet_Idx, $val=blocknet_Val,  $destination=blocked_nets, $mode=Input::REREAD]); 
 #       $pred(typ: Input::Event, left: blocknet_Idx, right: blocknet_Val = { left$epo = to_lower(left$epo); return T;) }]);
}


event zeek_done()
{
	#print fmt("bro-done"); 
	#print fmt("digested  %s records in blocked_nets", |Scan::blocked_nets|);
	#print fmt("blocked_nets %s", Scan::blocked_nets);

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

                #NOTICE([$note=HotSubnet,  $src_peer=get_local_event_peer(), $src=ip, $msg=fmt("%s", _msg)]);
                NOTICE([$note=HotSubnet,  $src=ip, $msg=fmt("%s", _msg)]);
        }

	if (ip in blocked_nets)
        {
                local msg = fmt ("%s is Scanner from blocknet %s", ip, blocked_nets[ip]);
                 NOTICE([$note=BlocknetsIP, $src=ip, $msg=fmt("%s", msg)]);
        }

}

