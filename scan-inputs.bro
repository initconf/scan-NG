module Scan;

#redef exit_only_after_terminate = T ; 
export {
        
	const read_files: set[string] = {} &redef;

	global whitelist_ip_file:  string = "/YURT/feeds/BRO-feeds/ip-whitelist.scan" &redef ; 
	global whitelist_subnet_file:  string = "/YURT/feeds/BRO-feeds/subnet-whitelist.scan" &redef ; 
	global blacklist_feeds: string =  "/YURT/feeds/BRO-feeds/blacklist.scan"  &redef ; 

        redef enum Notice::Type += {
                Whitelist, 
		Blacklist, 
        };

        type wl_ip_Idx: record {
                ip: addr;
        };

        type wl_ip_Val: record {
                ip: addr;
                comment: string &optional ;
        };
        
	type wl_subnet_Idx: record {
                nets: subnet ;
        };

        type wl_subnet_Val: record {
                nets: subnet ;
                comment: string &optional ;
	} ; 

        global whitelist_ip_table: table[addr] of wl_ip_Val = table() &redef ;
        global whitelist_subnet_table: table[subnet] of wl_subnet_Val = table() &redef ;

	type lineVals: record {
                d: string;
       	};

	const splitter: pattern = /\t/ ; 
	
	global Scan::m_w_add_ip: event(ip: addr, comment: string); 
	global Scan::m_w_update_ip: event(ip: addr, comment: string); 
	global Scan::m_w_remove_ip: event(ip: addr, comment: string); 
	
	global Scan::m_w_add_subnet: event(nets: subnet, comment: string); 
	global Scan::m_w_update_subnet: event(nets: subnet, comment: string); 
	global Scan::m_w_remove_subnet: event(nets: subnet, comment: string); 



}


@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Scan::m_w_(add|update|remove)_(ip|subnet)/;
@endif


event reporter_error(t: time , msg: string , location: string )
{

	if (/whitelist.scan/ in msg)
	{ 
		print fmt ("bakwas error: %s, %s, %s", t, msg, location); 
		### generate a notice 
	} 
} 
	


event read_whitelist_ip(description: Input::TableDescription, tpe: Input::Event, left: wl_ip_Idx, right: wl_ip_Val)
{


	local ip = right$ip ; 
	local comment= right$comment ; 
	local wl: wl_ip_Val; 

        if ( tpe == Input::EVENT_NEW ) 
	{
                log_reporter(fmt (" scan-inputs.bro : NEW IP %s", ip), 0);
			
		whitelist_ip_table[ip]=wl ; 
		
		whitelist_ip_table[ip]$ip = ip; 
		whitelist_ip_table[ip]$comment= comment; 

	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_add_ip(ip, comment) ; 
	@endif	

        }
        
	if (tpe == Input::EVENT_CHANGED) {
                log_reporter(fmt (" scan-inputs.bro : CHANGED IP %s, %s", ip, comment), 0);

		whitelist_ip_table[ip]$comment= comment; 

	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_update_ip(ip, comment) ; 
	@endif	
        }


        if (tpe == Input::EVENT_REMOVED ) {
                log_reporter(fmt (" scan-inputs.bro : REMOVED IP %s", ip), 0);

		delete whitelist_ip_table[ip]; 
	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_remove_ip(ip, comment) ; 
	@endif	
        }
	
	if ( ip !in whitelist_ip_table) 
	{
		whitelist_ip_table[ip]=wl ; 
	} 
		
	whitelist_ip_table[ip]$ip = ip; 
	whitelist_ip_table[ip]$comment= comment; 


}

event read_whitelist_subnet(description: Input::TableDescription, tpe: Input::Event, left: wl_subnet_Idx, right: wl_subnet_Val)
{

	
	local nets = right$nets; 
	local comment=right$comment ; 

	log_reporter(fmt (" scan-inputs.bro : type %s", tpe), 0);
        if ( tpe == Input::EVENT_NEW ) {

                log_reporter(fmt (" scan-inputs.bro : NEW Subnet %s", nets), 0);
		
		if (nets !in whitelist_subnet_table) 
		{
			local wl : wl_subnet_Val ; 
			whitelist_subnet_table[nets] = wl ; 
		} 

		whitelist_subnet_table[nets]$nets = nets; 
		whitelist_subnet_table[nets]$comment= comment; 

	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_add_subnet(nets, comment);
	@endif	
        }


        if (tpe == Input::EVENT_CHANGED) {
                log_reporter(fmt (" scan-inputs.bro : CHANGED Subnet  %s, %s", nets, comment), 0);
		whitelist_subnet_table[nets]$comment= comment; 
	
	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_update_subnet(nets, comment);
	@endif	
        }

        if (tpe == Input::EVENT_REMOVED) {
                log_reporter(fmt (" scan-inputs.bro : REMOVED Subnet  %s", nets),0 );
		delete whitelist_subnet_table[nets]; 

	@if ( Cluster::is_enabled() )
		event Scan::m_w_remove_subnet(nets, comment) ; 
	@endif	
        }


}





@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Scan::m_w_add_ip(ip: addr, comment: string)
        {
        log_reporter(fmt ("scan-inputs.bro: m_w_add_ip: %s, %s", ip, comment), 0);
		if ( ip !in whitelist_ip_table) 
		{
			local wl: wl_ip_Val; 
			whitelist_ip_table[ip]=wl ; 
		} 
		
		whitelist_ip_table[ip]$ip = ip; 
		whitelist_ip_table[ip]$comment= comment; 
        }

event Scan::m_w_update_ip(ip: addr, comment: string)
{
        log_reporter(fmt ("scan-inputs.bro: m_w_update_ip: %s, %s", ip, comment), 0);
	whitelist_ip_table[ip]$comment= comment; 
}

event Scan::m_w_remove_ip(ip: addr, comment: string)
{
        log_reporter(fmt ("scan-inputs.bro: m_w_remove_ip: %s, %s", ip, comment), 0);
	delete whitelist_ip_table[ip]; 
}


event Scan::m_w_add_subnet(nets: subnet, comment: string)
        {
        log_reporter(fmt ("scan-inputs.bro: m_w_add_subnet: %s, %s", nets, comment), 0);
		if (nets !in whitelist_subnet_table) 
		{
			local wl : wl_subnet_Val ; 
			whitelist_subnet_table[nets] = wl ; 
		} 

		whitelist_subnet_table[nets]$nets = nets; 
		whitelist_subnet_table[nets]$comment = comment;
	} 


event Scan::m_w_update_subnet(nets: subnet, comment: string)
{
        log_reporter(fmt ("scan-inputs.bro: m_w_update_subnet: %s, %s", nets, comment), 0);
	whitelist_subnet_table[nets]$comment = comment;
}

event Scan::m_w_remove_subnet(nets: subnet, comment: string)
{

        log_reporter(fmt ("scan-inputs.bro: m_w_remove_subnet: %s, %s", nets, comment), 0);
	delete whitelist_subnet_table[nets]; 
}
@endif


event update_whitelist()
{
	if (|whitelist_ip_table| <= 0)
	{ 
		 Input::force_update("whitelist_ip");
	} 
	
	if (|whitelist_subnet_table| <= 0)
	{ 
		 Input::force_update("whitelist_subnet");
	} 

	### schedule 5 mins { update_whitelist() } ; 
}


event read_whitelist()
{
        if ( ! Cluster::is_enabled() ||
             Cluster::local_node_type() == Cluster::MANAGER )
                {
				Input::add_table([$source=whitelist_ip_file, $name="whitelist_ip", $idx=wl_ip_Idx, 
				$val=wl_ip_Val,  $destination=whitelist_ip_table, $mode=Input::REREAD,$ev=read_whitelist_ip]);

				Input::add_table([$source=whitelist_subnet_file, $name="whitelist_subnet", 
				$idx=wl_subnet_Idx, $val=wl_subnet_Val,  $destination=whitelist_subnet_table, 
				$mode=Input::REREAD,$ev=read_whitelist_subnet]);
                }

	### schedule 1 mins { update_whitelist() } ; 
}


event bro_init() &priority=5
        {

	schedule 30 secs { read_whitelist() }; 

        }


event bro_done()
{
	#for ( ip in whitelist_ip_table)
	#{
	#	print fmt ("%s %s", ip , whitelist_ip_table[ip]); 
	#} 
	#for (nets in whitelist_subnet_table)
	#{
	#	print fmt ("%s %s", nets, whitelist_subnet_table[nets]); 
	#} 
}



