# module to rely on the fact that multiple
# scanners are often coming from same /24 or /64
# so just knock them on the very first connection
# once confidence is hight that subnet is bad

module Scan;

export {
        global activate_SubnetKnock = F &redef;

        redef enum Notice::Type += {
                SubnetKnock,
        };

        global Scan::filterate_SubnetKnock: function(c: connection, darknet: bool): string;
        global Scan::check_SubnetKnock: function(cid: conn_id, established: bool, reverse: bool): bool;
}

function Scan::filterate_SubnetKnock(c: connection, darknet: bool): string
{
	local rvalue ="";

	if (c$id$orig_h in hs)
		rvalue = "S";

        if ( Scan::isHotSubnet(c$id$orig_h) )
                rvalue = "S" ;

                return rvalue ;
}

function Scan::check_SubnetKnock(cid: conn_id, established: bool, reverse: bool): bool
{
        local result = F;
        local orig = cid$orig_h;
        local dport = cid$resp_p;

        local orig_loc = lookup_location(orig);
        local flux_density = check_port_flux_density(dport, orig);
	local distance = 0.0;
        distance = haversine_distance_ip(orig, cid$resp_h);

        local s = get_subnet(orig);

        if ( isHotSubnet(orig) )
        {
                # make sure there is country code
                local cc = orig_loc?$country_code ? orig_loc$country_code : "";

                local _msg = fmt("%s scanned a total of 1 hosts %s on [%s] (HotSubnet: %s, port-flux-density: %s) (origin: %s distance: %.2f miles)", orig, cid$resp_h,
                    cid$resp_p, s, flux_density, cc, distance);

                NOTICE([$note=SubnetKnock, $src=orig, $p=cid$resp_p, $msg=fmt("%s", _msg)]);
		return T;
        }

	return F;
}
