module Scan;

export {
	redef enum Notice::Type += {
		PortScan,
		AddressScan,
	};

	global service_udp_requires_response = T;
	global port_scanner: table[addr] of table[addr] of table[port] of count
	    &read_expire=1 days;
	global check_port_scan: function(orig: addr, resp: addr, svc: port);

	const threshold: vector of count = {
		30,
		100,
		500,
		1000,
		2000,
		10000,
		20000,
		10000,
		15000,
		20000,
		50000,
		100000,
	} &redef;

	global port_idx: table[addr, addr] of count &default=0 &read_expire=1 day &redef;

	global ip_idx: table[addr] of count &default=0 &read_expire=1 day &redef;

	global udp_ip_port_idx: table[addr, port] of count &default=0 &read_expire=1 day &redef;
}

function check_addresscan_thresh(v: vector of count, idx: table[addr] of count,
    orig: addr, n: count): bool
{
	if ( idx[orig] < |v| && n >= v[idx[orig]] ) {
		++idx[orig];
		return ( T );
	} else
		return ( F );
}

function check_portscan_thresh(v: vector of count, idx: table[addr, addr] of count,
    orig: addr, resp: addr, n: count): bool
{
	if ( idx[orig, resp] < |v| && n >= v[idx[orig, resp]] ) {
		++idx[orig, resp];
		return ( T );
	} else
		return ( F );
}

function has_active_service(c: connection): bool
{
	local proto = get_port_transport_proto(c$id$resp_p);

	switch ( proto ) {
		case tcp:
			# Not a service unless the TCP server did a handshake (SYN+ACK).
			if ( c$resp$state == TCP_ESTABLISHED
			    || c$resp$state == TCP_CLOSED
			    || c$resp$state == TCP_PARTIAL
			    || /h/ in c$history )
				return T;
			return F;
		case udp:
			# Not a service unless UDP server has sent something (or the option
			# to not care about that is set).
			if ( Scan::service_udp_requires_response )
				return c$resp$state == UDP_ACTIVE;
			return T;
		case icmp:
			# ICMP is not considered a service.
			return F;
		default:
			# Unknown/other transport not considered a service for now.
			return F;
	}
}

event connection_state_remove(c: connection)
{
	local orig = c$id$orig_h;
	local resp = c$id$resp_h;
	local svc = c$id$resp_p;

	if ( ! has_active_service(c) )
		check_port_scan(orig, resp, svc);
}

event udp_request(u: connection)
{
	local orig = u$id$orig_h;
	local resp = u$id$resp_h;
	local svc = u$id$resp_p;

	if ( ! has_active_service(u) )
		check_port_scan(orig, resp, svc);
}

function check_port_scan(orig: addr, resp: addr, svc: port)
{
	if ( orig !in port_scanner )
		port_scanner[orig] = table();

	if ( resp !in port_scanner[orig] )
		port_scanner[orig][resp] = table();

	if ( svc !in port_scanner[orig][resp] )
		port_scanner[orig][resp][svc] = 0;

	port_scanner[orig][resp][svc] += 1;

	local n = |port_scanner[orig][resp]|;

	local check_thresh = check_portscan_thresh(threshold, port_idx, orig, resp, n);

	if ( check_thresh ) {
		NOTICE([
		    $note=Scan::PortScan,
		    $src=orig,
		    $p=svc,
		    $n=n,
		    $msg=fmt("%s has scanned %d ports of %s", orig, n, resp)]);
	}

	n = |port_scanner[orig]|;

	local check_add_thresh = check_addresscan_thresh(threshold, ip_idx, orig, n);

	if ( check_add_thresh ) {
		local port_list: set[port];

		for ( r in port_scanner[orig] )
			for ( p in port_scanner[orig][r] )
				add port_list[p];

		local pl = "[";
		for ( pp in port_list )
			pl += fmt("%s ", pp);
		pl += "]";

		NOTICE([
		    $note=Scan::AddressScan,
		    $src=orig,
		    $n=n,
		    $msg=fmt("%s has scanned %d hosts on [%s] ports", orig, n, |port_list|)]);
	}
}

event zeek_done()
{
	return;

	for ( s in port_scanner )
		for ( d in port_scanner[s] )
			print fmt("%s scanned %s on %s ports", s, d, |port_scanner[s][d]|);
#for (p in port_scanner[s][d])
#print fmt("%s %s", p, port_scanner[s][d][p]);
}
