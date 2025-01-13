module Scan;

export {
	global outgoing_SF: set[addr] &read_expire=6 hrs ; #&backend=Broker::MEMORY;
	global conn_duration: set[addr] &read_expire=6hrs ; #&backend=Broker::MEMORY;

	redef enum Notice::Type += {
		OutgoingSF, # If TCP_ESTABLISHED to remote Scanner
		LongDuration,
	};

	global check_conn_history: function(ip: addr): bool;
}

event Scan::m_w_add_scanner(ss: Scan::scan_info)
{
	local ip = ss$scanner;

	# not sure why we are doing subnet
	# this is not forgiving and FP prone
	#local ds = get_subnet(ip);

	if ( ip in outgoing_SF ) {
		NOTICE([
		    $note=OutgoingSF,
		    $src=ip,
		    $msg=fmt("outgoing SF to IP flagged as scanner %s", ip)]);
	}

	if ( ip in conn_duration ) {
		NOTICE([
		    $note=LongDuration,
		    $src=ip,
		    $msg=fmt("known long duration connections from this scanner IP: %s", ip)]);
	}
}

# good guys == IP which successfully accepted a connection
# originating from the local_nets

event connection_established(c: connection) &priority=-5
{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ( src !in Site::local_nets )
		return;

	if ( c$resp$state != TCP_ESTABLISHED )
		return;

	local trans = get_port_transport_proto(c$id$orig_p);
	if (trans != tcp)
		return;

	if (/\^/ in c$history)
		return;

 add outgoing_SF[dst];
}

event connection_state_remove(c: connection) &priority=-5
{
	#if ( c$conn$proto == udp || c$conn$proto == icmp )
	#	return;

	local src = c$id$orig_h;

	if ( src !in Site::local_nets )
		return;

	if ( c$duration > 60 secs ) {
		add conn_duration[src];
	}
}
