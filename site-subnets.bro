module Site  ; 

#redef exit_only_after_terminate = T ; 
export {

	redef enum Notice::Type += {
                #### Indicates that an MD5 sum was calculated for an HTTP response body.
                Watched_Subnet,	
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

	global subnet_feed="/YURT/feeds/BRO-feeds/LBL-subnets.csv-LATEST_BRO" &redef ; 

} 



#### FAILURE-CHECK 
### we catch the error in subnet feed is empty and populate subnet_table with local_nets 
### so that LandMine detection doesn't block accidently 

event reporter_error(t: time , msg: string , location: string )
{

        if (/LBL-subnets.csv-LATEST_BRO.2\/Input::READER_ASCII: Init failed/ in msg)
        if (subnet_feed in msg)
	{ 
		for (nets in Site::local_nets)
               	{
			print fmt("nets: %s", nets); 
			local sv: subnet_Val = [$Network=nets, $Gateway=1.1.1.1, $Enclaves="Site", $Use="Filling the empty subnet table"]; 
              		Site::subnet_table[nets] = sv ; 
		}
	} 
	
}



event Input::end_of_data(name: string, source: string)                                                         
{                                                                         
	print fmt ("name is %s source is %s", name, source); 
        print fmt("digested  %s records in %s",|source|, source);
		
	# since subnet table is zero size
       	# we poulate with local_nets
	
	if (|Site::subnet_table| == 0)
	{       
		for (nets in Site::local_nets)
                {       local sv: subnet_Val ;
                        subnet_table[nets] = sv ;
               	 }
	} 
} 

event bro_init() &priority=10
{
        Input::add_table([$source=subnet_feed, $name="subnet_table", $idx=subnet_Idx, $val=subnet_Val,  $destination=subnet_table, $mode=Input::REREAD]);  
        

 ####     Input::add_table([$source=subnet_feed, $name="subnet_table", $idx=subnet_Idx, $val=subnet_Val,  $destination=subnet_table, $mode=Input::REREAD]); 
 #       $pred(typ: Input::Event, left: subnet_Idx, right: subnet_Val = { left$epo = to_lower(left$epo); return T;) }]);
}


event bro_done()
{
	#print fmt("bro-done subnet-bro"); 
	#print fmt("digested  %s records in subnet_table", |Site::subnet_table|);
	#print fmt("subnet_table %s", Site::subnet_table);

} 


