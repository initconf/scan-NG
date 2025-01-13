# $Id: trw.bro 3297 2006-06-18 00:56:58Z vern $
#
# Load this file to actiate TRW analysis.

@load ./trw-impl

redef TRW::use_TRW_algorithm = T;

function conn_state(c: connection, trans: transport_proto): string
{
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
	local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

	if ( trans == tcp ) {
		if ( rs == TCP_RESET ) {
			if ( os == TCP_SYN_SENT
			    || os == TCP_SYN_ACK_SENT
			    || ( os == TCP_RESET && c$orig$size == 0 && c$resp$size == 0 ) )
				return "REJ";
			else if ( o_inactive )
				return "RSTRH";
			else
				return "RSTR";
		} else if ( os == TCP_RESET )
			return r_inactive ? "RSTOS0" : "RSTO";
		else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
			return "SF";
		else if ( os == TCP_CLOSED )
			return r_inactive ? "SH" : "S2";
		else if ( rs == TCP_CLOSED )
			return o_inactive ? "SHR" : "S3";
		else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
			return "S0";
		else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
			return "S1";
		else
			return "OTH";
	} 
	else if ( trans == udp ) {
		if ( os == UDP_ACTIVE )
			return rs == UDP_ACTIVE ? "SF" : "S0";
		else
			return rs == UDP_ACTIVE ? "SHR" : "OTH";
	} 
	else
		return "OTH";
}
#event connection_established(c: connection)
#        {
#        local is_reverse_scan = (c$orig$state == TCP_INACTIVE);
#        local trans = get_port_transport_proto(c$id$orig_p);
#        if ( trans == tcp && ! is_reverse_scan && TRW::use_TRW_algorithm )
#                TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event connection_attempt(c: connection)
#        {
#        local trans = get_port_transport_proto(c$id$orig_p);
#        if ( trans == tcp && TRW::use_TRW_algorithm )
#                TRW::check_TRW_scan(c, conn_state(c, trans), F);
#        }
#
#event connection_rejected(c: connection)
#        {
#        local is_reverse_scan = c$orig$state == TCP_RESET;
#
#        local trans = get_port_transport_proto(c$id$orig_p);
#        if ( trans == tcp && TRW::use_TRW_algorithm )
#                TRW::check_TRW_scan(c, conn_state(c, trans), is_reverse_scan);
#        }
