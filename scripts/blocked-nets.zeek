module Scan;

#redef exit_only_after_terminate = T ;

export {
	redef enum Notice::Type += {
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
		BLOCK_FLAVOR: string &optional;
	};

	global blocked_nets: table[subnet] of blocknet_Val = table() &redef;
	global blocknet_feed = "/YURT/feeds/BRO-feeds/WIRED.blocknet" &redef;
}

# FAILURE-CHECK
# we catch the error in subnet feed is empty and populate blocked_nets with local_nets
# so that LandMine detection doesn't block accidently

hook Notice::policy(n: Notice::Info)
{
	if ( n$note == Scan::BlocknetsFileReadFail ) {
		add n$actions[Notice::ACTION_EMAIL];
	}
}

# handle this failure
# Reporter::WARNING  /YURT/feeds/BRO-feeds/WIRED.blocknet.2/Input::READER_ASCII:
#	Init: cannot open /YURT/feeds/BRO-feeds/WIRED.blocknet.2    (empty)

event reporter_warning(t: time, msg: string, location: string)
{
	if ( /WIRED.blocknet.*\/Input::READER_ASCII: Init: cannot open/ in msg ) {
		NOTICE([$note=BlocknetsFileReadFail, $msg=fmt("%s", msg)]);
	}
}

event Input::end_of_data(name: string, source: string)
{
	if ( /WIRED.blocknet/ in name ) {
		print fmt("name=%s, source=%s, records=%s", name, source, |source|);
	}
# since subnet table is zero size
# we poulate with local_nets

# FIXME
#if (|Scan::blocked_nets| == 0)
#{
#	for (nets in Site::local_nets)
#            {       local sv: blocknet_Val ;
#                    blocked_nets[nets] = sv ;
#           	 }
#}
}

event line(description: Input::TableDescription, tpe: Input::Event,
    left: blocknet_Idx, right: blocknet_Val)
{
	local msg: string;

	if ( tpe == Input::EVENT_NEW ) { #print fmt ("NEW");
	}

	if ( tpe == Input::EVENT_CHANGED ) { #print fmt ("CHANGED");
	}

	if ( tpe == Input::EVENT_REMOVED ) { #print fmt ("REMOVED");
	}
}

event zeek_init() &priority=10
{
	Input::add_table([
	    $source=blocknet_feed,
	    $name="blocked_nets",
	    $idx=blocknet_Idx,
	    $val=blocknet_Val,
	    $destination=blocked_nets,
	    $mode=Input::REREAD,
	    $ev=line]);

#     Input::add_table([$source=blocknet_feed, $name="blocked_nets", 
#	$idx=blocknet_Idx, $val=blocknet_Val,  $destination=blocked_nets, $mode=Input::REREAD]);
#       $pred(typ: Input::Event, left: blocknet_Idx, right: blocknet_Val = 
#		{ left$epo = to_lower(left$epo); return T;) }]);
}

event zeek_done()
{
#print fmt("bro-done");
#print fmt("digested  %s records in blocked_nets", |Scan::blocked_nets|);
#print fmt("blocked_nets %s", Scan::blocked_nets);
}

