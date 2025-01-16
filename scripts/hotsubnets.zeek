module Scan;

#redef exit_only_after_terminate = T ;

export {
	redef enum Notice::Type += {
		HotSubnet, # Too many scanners originating from this subnet
	};

	global hot_subnets: table[subnet] of set[addr] &create_expire=7days;
	global hs: set[subnet] &backend=Broker::MEMORY &create_expire=7days;
	global hot_subnets_idx: table[subnet] of count &create_expire=7days;

	global hot_subnets_threshold: vector of count = { 10, 25, 100, 200, 255, 500,
	    1000, 5000, 10000, 20000, 30000, 50000, 100000,  };

	global Scan::AddHotSubnet: function(ip: addr);
	global Scan::evHotSubnet: event(ip: addr);
	global Scan::isHotSubnet: function(ip: addr): bool;

	global check_subnet_threshold: function(v: vector of count, idx: table[subnet] of
	    count, orig: subnet, n: count): bool;
}

function check_subnet_threshold(v: vector of count, idx: table[subnet] of count,
    orig: subnet, n: count): bool
	{
	if ( orig !in idx )
		idx[orig] = 0;

	# print fmt ("orig: %s and IDX_orig: %s and n is: %s and v[idx[orig]] is: %s", orig, idx[orig], n, v[idx[orig]]);

	if ( idx[orig] < |v| && n >= v[idx[orig]] )
		{
		++idx[orig];

		return ( T );
		}
	else
		return ( F );
	}

function Scan::AddHotSubnet(orig: addr)
	{
	if ( orig in Site::local_nets )
		return;

	if ( orig in Scan::ignore_hot_subnets )
		return;

@ifdef ( YURT::NEVER_DROP_NETS )
	if ( orig in YURT::NEVER_DROP_NETS )
		return;
@endif

	event Scan::evHotSubnet(orig);
	}

#event connection_state_remove(c: connection)
#{
#        # only external IPs
#        if ( c$id$orig_h in Site::local_nets )
#                return;
#
#	if (c$id$orig_h in Scan::ignore_hot_subnets)
#		return;
#
#@ifdef (YURT::NEVER_DROP_NETS)
#	if (c$id$orig_h in YURT::NEVER_DROP_NETS)
#		return;
#@endif
#
#        local id = c$id;
#        local service = id$resp_p;
#
#        local trans = get_port_transport_proto(service);
#
#        # don't operate on a connection which responder
#        # sends data back in a tcp connection ie c$history = d
#
#        if ( (trans == tcp)
#        && (c$conn$conn_state == "S0")
#        && ( /d|D/ !in c$history ) ) {
#
#                # 2022-07-26 - if a scan-candidate
#                # enable subnet scan heuristics
#                # as long as no data is transferred
#                if (c$id$orig_h in Scan::scan_candidates && c$id$resp_p !in ignore_hot_subnets_ports)
#                {
#                        local ss = get_subnet(c$id$orig_h);
#                        #AddHotSubnet(c$id$orig_h);
#                }
#       }
#}

event Scan::evHotSubnet(ip: addr)
	{
	# check for subnet scanners

	local scanner_subnet = get_subnet(ip);

	#if ( scanner_subnet !in hot_subnets ) {
	if ( ! check_subnet(scanner_subnet, hot_subnets) )
		{
		local a: set[addr];
		hot_subnets[scanner_subnet] = a;
		}

	add hot_subnets[scanner_subnet][ip];
	add hs[scanner_subnet];

	local n = |hot_subnets[scanner_subnet]|;

	local result = F;
	result = check_subnet_threshold(hot_subnets_threshold, hot_subnets_idx,
	    scanner_subnet, n);

	if ( result )
		{
		local _msg = fmt("%s has %s scanners originating from it", scanner_subnet, n);
		NOTICE([ $note=HotSubnet, $src=ip, $msg=fmt("%s", _msg) ]);
		}

	#	if ( ip in blocked_nets ) {
	#		local msg = fmt("%s is Scanner from blocknet %s", ip, blocked_nets[ip]);
	#		NOTICE([$note=BlocknetsIP, $src=ip, $msg=fmt("%s", msg)]);
	#	}
	}

function Scan::isHotSubnet(ip: addr): bool
	{
	local ss = get_subnet(ip);

	#check_subnet is a bif to check membership
	# of a subnet in a table
	# more accurate than `in`
	if ( ! check_subnet(ss, hot_subnets) )
		return F;

	if ( hot_subnets_idx[ss] >= 1 )
		return T;
	else
		return F;
	}
