module Scan;

export {
	redef enum Notice::Type += {
		Interest,
	};

	type probes: record {
		remote_sub: subnet;
		remotes: set[addr];
		svc: port;
		};

	global Scan::evHotInterest: event(cid: conn_id);

	global interests: table[addr, port] of table [subnet] of probes &create_expire=7 days;
        global interests_idx: table[subnet] of count &create_expire=7 days;

        global interests_threshold: vector of count = {
		4,
                10,
                25,
                100,
                200,
                255,
                500,
                1000,
                5000,
                10000,
                20000,
                30000,
                50000,
                100000,
        };
}

function Scan::AddInterests(cid: conn_id)
{
	local orig = cid$orig_h;
        local service = cid$resp_p;
	local resp=cid$resp_h;

	@if ( Cluster::is_enabled() )
		local scan_sub = get_subnet(orig);
		#local u = fmt ("%s%s",resp,service);
		Cluster::publish_hrw(Cluster::proxy_pool, scan_sub, Scan::evHotInterest, cid);
	@else
		event Scan::evHotInterest(cid);
	@endif

}


event connection_state_remove(c: connection)
{
	local cid=c$id;
        local service = cid$resp_p;

        # only external IPs
        if ( c$id$orig_h in Site::local_nets )
                return;

	local ss = get_subnet(c$id$orig_h);

	if (check_subnet(ss,hot_subnets))
		return;

        local id = c$id;


        local trans = get_port_transport_proto(service);

        # don't operate on a connection which responder
        # sends data back in a tcp connection ie c$history = d

        if ( (trans == tcp)
        && ( /d|D|ShFgfG/ in c$history || "SF" in c$conn$conn_state) ) {
		AddInterests(c$id);
        }
}

event Scan::evHotInterest(cid: conn_id)
{
	# check for subnet scanners

	local resp=cid$resp_h;
	local orig=cid$orig_h;
	local svc=cid$resp_p;

	local ss = get_subnet(orig);

	#if ( scanner_subnet !in hot_subnets ) {
	if ([resp,svc] !in interests)
		interests[resp,svc] = table();

	if (ss !in interests[resp,svc])
	{
		local p: probes;
		interests[resp,svc][ss] = p;
	}


	interests[resp,svc][ss]$remote_sub = ss;
	add interests[resp,svc][ss]$remotes [orig];
	interests[resp,svc][ss]$svc = cid$resp_p;

	local n = |interests[resp,svc][ss]$remotes|;
	#print fmt ("n is %s", n);

	local result = F;
	result = check_subnet_threshold(interests_threshold, interests_idx, ss, n);

	if (result)
	{
		local _msg = fmt("%s has %s hosts probing %s on %s", ss, n, resp, cid$resp_p);
		NOTICE([$note=Interest, $src=resp, $msg=fmt("%s", _msg)]);
	}
}
