module Site  ; 

redef exit_only_after_terminate = T ; 
export {

	redef enum Notice::Type += {
                # Indicates that an MD5 sum was calculated for an HTTP response body.
                Watched_Subnet,	
		AllocatedSubnetRemoved, 
		DarknetSubnetAdded, 
		SubnetTableZero, 
		ReactivatingSubnetTable, 
		MissingSubnetsFeed, 
	}; 

	type subnet_Idx: record {
		Network: subnet; 
	};

	type subnet_Val: record {
		Network: subnet; 
		Gateway : addr &optional;  
		Enclaves: string &optional ; 
		Use: string &optional ;
	};


	global subnet_table: table[subnet] of subnet_Val = table() &redef ; 
	global subnet_feed="/feeds/BRO-feeds/LBL-subnets.csv-LATEST_BRO" &redef ; 

	# flag to make sure LandMine doesn't activate until 
	# subnet_feed is fully read  - 2021-02-25 ash 

	global SubnetCountToActivteLandMine = 65536 &redef ;

	# a cache to keep memory of allocated subnets removed
	# from subnets.csv file for another hour before calling 
	# that subnet a DarkNet 


	global WATCH_REMOVED_ALLOCATED_SUBNET= 2 hrs &redef  ; 

	global expire_allocated_cache: function(t: set[subnet], idx: subnet): interval; 	
	#global allocated_cache: table[subnet] of subnet_val = table() 
	global allocated_cache: set[subnet] =set() 
			&create_expire = WATCH_REMOVED_ALLOCATED_SUBNET &expire_func=expire_allocated_cache ;

	

} 


@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (!Cluster::is_enabled()))

hook Notice::policy (n: Notice::Info) {
   if ( n$note == Site::DarknetSubnetAdded) 
               { add n$actions[Notice::ACTION_LOG];}
   if (n$note == Site::AllocatedSubnetRemoved) 
               { add n$actions[Notice::ACTION_LOG];}
   if (n$note == Site::SubnetTableZero) 
               { add n$actions[Notice::ACTION_LOG];}
   if (n$note == Site::ReactivatingSubnetTable) 
               { add n$actions[Notice::ACTION_LOG];}
   if (n$note == Site::MissingSubnetsFeed) 
               { add n$actions[Notice::ACTION_LOG];}
  }

@endif 


function expire_allocated_cache(t: set[subnet], idx: subnet): interval 
{
	local _msg = fmt ("Expiring the WATCH on REMOVED_ALLOCATED_SUBNET %s ", idx); 

	NOTICE([$note=DarknetSubnetAdded, $msg=fmt("%s", _msg)]);	

	return 0 secs ; 
} 


# FAILURE-CHECK 
# we catch the error in subnet feed is empty and populate subnet_table with local_nets 
# so that LandMine detection doesn't block accidently 

event reporter_warning(t: time , msg: string , location: string )
{

	local file_pat = fmt ("%s\/Input::READER_ASCII",subnet_feed); 

        if (file_pat in msg)
        {
		NOTICE([$note=MissingSubnetsFeed, $msg=fmt("%s", msg)]);	
        	if (subnet_feed in msg)
		{ 
		for (nets in Site::local_nets)
               	{
			#print fmt("nets: %s", nets); 
			local sv: subnet_Val = [$Network=nets, $Gateway=0.0.0.0, $Enclaves="Site", $Use="Filling the empty subnet table"]; 
              		Site::subnet_table[nets] = sv ; 
		}
		} 
	} 
	
}

event read_subnet_feed(description: Input::TableDescription, tpe: Input::Event, left: subnet_Idx, right: subnet_Val)
{
        if ( tpe == Input::EVENT_NEW || tpe == Input::EVENT_CHANGED) {
	
		if (left$Network in allocated_cache) 
			delete allocated_cache[left$Network]; 
	} 

        if ( tpe == Input::EVENT_REMOVED) {
		
		# we will still consider the removed subnet 
		# as allocated for WATCH_REMOVED_ALLOCATED_SUBNET time 
		
		add allocated_cache [right$Network]; 
	
		local _msg = fmt ("Subnet is removed from the list of allocated subnets: %s -> %s", left, right); 
		NOTICE([$note=AllocatedSubnetRemoved, $msg=fmt("%s", _msg), $identifier=cat("AllocatedSubnetRemoved"), $suppress_for=6 hrs]);	
	} 
} 


event Input::end_of_data(name: string, source: string)                                                         
{                                                                         
	if (source != subnet_feed) 
		return; 

	if ( subnet_feed in source  )
	{ 
		#print fmt ("1. name is %s source is %s", name, source); 
		#print fmt("2. digested  %s records in %s",|Site::subnet_table|, source);
		
	# since subnet table is zero size
       	# we poulate with local_nets
	
	if (|Site::subnet_table| == 0)
	{ 
		local _msg = fmt ("Looks like subnet Table is %s", |Site::subnet_table|) ; 

		for (nets in Site::local_nets)
                {       #local sv: subnet_Val ;
                        #subnet_table[nets] = sv ;
			subnet_table[nets] = [$Network=nets, $Gateway=0.0.0.0, $Enclaves="Site", $Use="Filling the empty subnet table"];
               	 }
		
		_msg += fmt (" expanded subnet table to local_nets: %s", subnet_table); 

		NOTICE([$note=SubnetTableZero, $msg=fmt("%s", _msg)]);	
	} 
	else 
		SubnetCountToActivteLandMine = |Site::subnet_table| ; 

	
	if (|Site::subnet_table| > |Site::local_nets|) 
	{ 
		for (nets in Site::local_nets)
		{ 
			if (nets in subnet_table && /Filling/ in subnet_table[nets]$Use) 
			{ 
				delete subnet_table[nets] ; 
			} 
		
                }  
		
		_msg = fmt ("Repopulated subnet table with %s Entries, removing local_nets automatically to activate LandMine again", 
						SubnetCountToActivteLandMine) ; 
		#NOTICE([$note=ReactivatingSubnetTable, $msg=fmt("%s", _msg)]);	
	} 

	} 
} 

event zeek_init() &priority=10
{
        Input::add_table([$source=subnet_feed, $name="subnet_table", 
			$idx=subnet_Idx, $val=subnet_Val,  
			$destination=subnet_table, $mode=Input::REREAD, 
			$ev=read_subnet_feed]);  

 #     Input::add_table([$source=subnet_feed, $name="subnet_table", $idx=subnet_Idx, $val=subnet_Val,  $destination=subnet_table, $mode=Input::REREAD]); 
 #       $pred(typ: Input::Event, left: subnet_Idx, right: subnet_Val = { left$epo = to_lower(left$epo); return T;) }]);
}


event zeek_done()
{
	#print fmt("bro-done subnet-bro"); 
	print fmt("digested  %s records in subnet_table", |Site::subnet_table|);
	#print fmt("subnet_table %s", Site::subnet_table);

} 


