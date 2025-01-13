module Scan;

#redef exit_only_after_terminate = T ;

export {
	global PURGE_ON_WHITELIST = T;

	redef enum Notice::Type += {
		PurgeOnWhitelist,
		WhitelistAdd,
		WhitelistRemoved,
		WhitelistChanged,
	};

	const read_whitelist_timer: interval = 10 secs;
	const update_whitelist_timer: interval = 5 mins;

	const read_files: set[string] = { } &redef;

	global whitelist_ip_file: string = "/YURT/feeds/BRO-feeds/ip-whitelist.scan.2" &redef;
	global whitelist_subnet_file: string =
	    "/YURT/feeds/BRO-feeds/subnet-whitelist.scan.2" &redef;
	global blacklist_feeds: string = "/YURT/feeds/BRO-feeds/blacklist.scan" &redef;

	redef enum Notice::Type += {
		Whitelist,
		Blacklist,
	};

	type wl_ip_Idx: record {
		ip: addr;
	};

	type wl_ip_Val: record {
		ip: addr;
		comment: string &optional;
	};

	type wl_subnet_Idx: record {
		nets: subnet;
	};

	type wl_subnet_Val: record {
		nets: subnet;
		comment: string &optional;
	};

	global whitelist_ip_table: table[addr] of wl_ip_Val = table();
	global whitelist_subnet_table: table[subnet] of wl_subnet_Val = table();

	type lineVals: record {
		d: string;
	};

	const splitter: pattern = /\t/;

	global Scan::m_w_add_ip: event(ip: addr, comment: string);
	global Scan::m_w_update_ip: event(ip: addr, comment: string);
	global Scan::m_w_remove_ip: event(ip: addr, comment: string);

	global Scan::m_w_add_subnet: event(nets: subnet, comment: string);
	global Scan::m_w_update_subnet: event(nets: subnet, comment: string);
	global Scan::m_w_remove_subnet: event(nets: subnet, comment: string);
}

event reporter_error(t: time, msg: string, location: string)
{
	if ( /whitelist.scan/ in msg ) {
		print fmt("bakwas error: %s, %s, %s", t, msg, location);
	# generate a notice
	}
}

event read_whitelist_ip(description: Input::TableDescription, tpe: Input::Event,
    left: wl_ip_Idx, right: wl_ip_Val)
{
	local _msg = "";
	local ip = right$ip;
	local comment = right$comment;
	local wl: wl_ip_Val;

	if ( tpe == Input::EVENT_NEW ) {
		#log_reporter(fmt (" scan-inputs.bro : NEW IP %s", ip), 0);

		whitelist_ip_table[ip] = wl;

		whitelist_ip_table[ip]$ip = ip;
		whitelist_ip_table[ip]$comment = comment;

		_msg = fmt("%s: %s", ip, comment);
		NOTICE([$note=WhitelistAdd, $src=ip, $msg=fmt("%s", _msg)]);

		if ( PURGE_ON_WHITELIST && Scan::is_catch_release_active(ip) ) {
			_msg = fmt("%s is removed from known_scanners after whitelist: %s", ip,
			    known_scanners[ip]);
			delete known_scanners[ip];

@ifdef ( NetControl::unblock_address_catch_release )
			if ( NetControl::unblock_address_catch_release(ip, _msg) ) {
				NOTICE([$note=PurgeOnWhitelist, $src=ip, $msg=fmt("%s", _msg)]);
			}
@endif
		}

@if ( Cluster::is_enabled() )
		Broker::publish(Cluster::proxy_topic, Scan::m_w_add_ip, ip, comment);
		#event Scan::m_w_add_ip(ip, comment) ;
@endif
	}

	if ( tpe == Input::EVENT_CHANGED ) {
		#log_reporter(fmt (" scan-inputs.bro : CHANGED IP %s, %s", ip, comment), 0);

		whitelist_ip_table[ip]$comment = comment;

		_msg = fmt("%s: %s", ip, comment);
		NOTICE([$note=WhitelistChanged, $src=ip, $msg=fmt("%s", _msg)]);

@if ( Cluster::is_enabled() )
		#event Scan::m_w_update_ip(ip, comment) ;
		Broker::publish(Cluster::proxy_topic, Scan::m_w_update_ip, ip, comment);
@endif
	}

	if ( tpe == Input::EVENT_REMOVED ) {
		#log_reporter(fmt (" scan-inputs.bro : REMOVED IP %s", ip), 0);

		delete whitelist_ip_table[ip];

		_msg = fmt("%s: %s", ip, comment);
		NOTICE([$note=WhitelistRemoved, $src=ip, $msg=fmt("%s", _msg)]);

@if ( Cluster::is_enabled() )
		#event Scan::m_w_remove_ip(ip, comment) ;
		Broker::publish(Cluster::proxy_topic, Scan::m_w_remove_ip, ip, comment);
@endif
	}

	if ( ip !in whitelist_ip_table ) {
		whitelist_ip_table[ip] = wl;
	}

	whitelist_ip_table[ip]$ip = ip;
	whitelist_ip_table[ip]$comment = comment;
}

event read_whitelist_subnet(description: Input::TableDescription,
    tpe: Input::Event, left: wl_subnet_Idx, right: wl_subnet_Val)
{
	local nets = right$nets;
	local comment = right$comment;
	local _msg = "";

	#log_reporter(fmt (" SUBNETS: scan-inputs.bro : type %s", tpe), 0);

	if ( tpe == Input::EVENT_NEW ) {
		#log_reporter(fmt (" scan-inputs.bro : NEW Subnet %s", nets), 0);

		if ( nets !in whitelist_subnet_table ) {
			local wl: wl_subnet_Val;
			whitelist_subnet_table[nets] = wl;
		}

		whitelist_subnet_table[nets]$nets = nets;
		whitelist_subnet_table[nets]$comment = comment;

		_msg = fmt("%s: %s", nets, comment);
		NOTICE([$note=WhitelistAdd, $msg=fmt("%s", _msg)]);

@if ( Cluster::is_enabled() )
		#event Scan::m_w_add_subnet(nets, comment);
		Broker::publish(Cluster::proxy_topic, Scan::m_w_add_subnet, nets, comment);
@endif
	}

	if ( tpe == Input::EVENT_CHANGED ) {
		#log_reporter(fmt (" scan-inputs.bro : CHANGED Subnet  %s, %s", nets, comment), 0);
		whitelist_subnet_table[nets]$comment = comment;

		_msg = fmt("%s: %s", nets, comment);
		NOTICE([$note=WhitelistChanged, $msg=fmt("%s", _msg)]);

@if ( Cluster::is_enabled() )
		#event Scan::m_w_update_subnet(nets, comment);
		Broker::publish(Cluster::proxy_topic, Scan::m_w_update_subnet, nets, comment);
@endif
	}

	if ( tpe == Input::EVENT_REMOVED ) {
		#log_reporter(fmt (" scan-inputs.bro : REMOVED Subnet  %s", nets),0 );
		delete whitelist_subnet_table[nets];

		_msg = fmt("%s: %s", nets, comment);
		NOTICE([$note=WhitelistRemoved, $msg=fmt("%s", _msg)]);

@if ( Cluster::is_enabled() )
		#event Scan::m_w_remove_subnet(nets, comment) ;
		Broker::publish(Cluster::proxy_topic, Scan::m_w_remove_subnet, nets, comment);
@endif
	}
}

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Scan::m_w_add_ip(ip: addr, comment: string)
{
	local _msg = "";
	#log_reporter(fmt ("scan-inputs.bro: m_w_add_ip: %s, %s", ip, comment), 0);

	if ( ip !in whitelist_ip_table ) {
		local wl: wl_ip_Val;
		whitelist_ip_table[ip] = wl;
	}

	whitelist_ip_table[ip]$ip = ip;
	whitelist_ip_table[ip]$comment = comment;

	# disable for the time-being to keep consistency with changed, removed
	# and webspiders are being logged already

	_msg = fmt("removing from known_scanners table due to whitelist: %s: %s", ip, comment);

	#NOTICE([$note=WhitelistAdd, $src=ip, $msg=fmt("%s", _msg)]);

	#if (PURGE_ON_WHITELIST && ip in known_scanners)
	if ( PURGE_ON_WHITELIST && is_catch_release_active(ip) ) {
		_msg = fmt("%s is removed from known_scanners after whitelist: %s", ip,
		    known_scanners[ip]);
		delete known_scanners[ip];

@ifdef ( NetControl::unblock_address_catch_release )
		if ( NetControl::unblock_address_catch_release(ip, _msg) ) {
			NOTICE([$note=PurgeOnWhitelist, $src=ip, $msg=fmt("%s", _msg)]);
		}
@endif
	}
}

event Scan::m_w_update_ip(ip: addr, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: m_w_update_ip: %s, %s", ip, comment), 0);
	whitelist_ip_table[ip]$comment = comment;
}

event Scan::m_w_remove_ip(ip: addr, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: m_w_remove_ip: %s, %s", ip, comment), 0);
	delete whitelist_ip_table[ip];
}

event Scan::m_w_add_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: m_w_add_subnet: %s, %s", nets, comment), 0);
	if ( nets !in whitelist_subnet_table ) {
		local wl: wl_subnet_Val;
		whitelist_subnet_table[nets] = wl;
	}

	whitelist_subnet_table[nets]$nets = nets;
	whitelist_subnet_table[nets]$comment = comment;

	if ( PURGE_ON_WHITELIST ) {
		for ( ip in known_scanners ) {
			if ( ip in nets ) {
				local _msg = fmt("%s is removed from known_scanners after %s whitelist: %s", ip, nets,
				    known_scanners[ip]);

				NOTICE([$note=PurgeOnWhitelist, $src=ip, $msg=fmt("%s", _msg)]);
				# ASH: FIXME : cannot delete inside a for loop
				# delete known_scanners[ip] ;

@ifdef ( NetControl::unblock_address_catch_release )
				NetControl::unblock_address_catch_release(ip, _msg);
@endif
			}
		}
	}
}

event Scan::m_w_update_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: m_w_update_subnet: %s, %s", nets, comment), 0);
	whitelist_subnet_table[nets]$comment = comment;
}

event Scan::m_w_remove_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: m_w_remove_subnet: %s, %s", nets, comment), 0);
	delete whitelist_subnet_table[nets];
}
@endif

event update_whitelist()
{
	#log_reporter(fmt ("%s running update_whitelist", network_time()), 0);
	#print fmt("%s", whitelist_ip_table);

	Input::force_update("whitelist_ip_scan");
	Input::force_update("whitelist_subnet_scan");

	schedule update_whitelist_timer { update_whitelist() };
}

event read_whitelist()
{
	if ( ! Cluster::is_enabled() || Cluster::local_node_type() ==
	    Cluster::MANAGER ) {
		Input::add_table([
		    $source=whitelist_ip_file,
		    $name="whitelist_ip_scan",
		    $idx=wl_ip_Idx,
		    $val=wl_ip_Val,
		    $destination=whitelist_ip_table,
		    $mode=Input::REREAD,
		    $ev=read_whitelist_ip]);

		Input::add_table([
		    $source=whitelist_subnet_file,
		    $name="whitelist_subnet_scan",
		    $idx=wl_subnet_Idx,
		    $val=wl_subnet_Val,
		    $destination=whitelist_subnet_table,
		    $mode=Input::REREAD,
		    $ev=read_whitelist_subnet]);
	}

#schedule update_whitelist_timer  { update_whitelist() } ;
}

event zeek_init() &priority=5
{
	schedule read_whitelist_timer { read_whitelist() };
}

event zeek_done()
{ #for ( ip in whitelist_ip_table)
#{
#	print fmt ("%s %s", ip , whitelist_ip_table[ip]);
#}
#for (nets in whitelist_subnet_table)
#{
#	print fmt ("%s %s", nets, whitelist_subnet_table[nets]);
#}
}
