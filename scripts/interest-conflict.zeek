module Scan;


export {

	redef enum Notice::Type += {
                Conflict,
        };

}

event Scan::evHotInterest(cid: conn_id)
{
        # check for subnet scanners

        local resp=cid$resp_h;
        local orig=cid$orig_h;
        local svc=cid$resp_p;

        local ss = get_subnet(orig);
	local _msg = "";

    if ( ss in Scan::hot_subnets && |Scan::hot_subnets[ss]| > 5 && interests_idx[ss] > 4 )
        {
                _msg = fmt ("%s flagged as Interests where as it is also Scan::HotSubnets: [ %s ]", ss, |Scan::hot_subnets[ss]|);
                NOTICE([$note=Conflict, $id=cid, $msg=fmt("%s", _msg)]);
        }

	#if (orig in Scan::hot_subnets && |Scan::hot_subnets[ss] > 5 && interests_idx[ss] > 4)
        #{
        #        _msg = fmt ("%s [%s] flagged as HotSubnets  %s where as it is also Interests: %s", orig, ss, Scan::interests_idx[ss], Scan::hot_subnets[ss]);
        #        NOTICE([$note=Conflict, $id=cid, $msg=fmt("%s", _msg)]);
        #}
}


event Scan::evHotSubnet(ip: addr)
{

	local ss = get_subnet(ip);

	if (ip in Scan::interests_idx && interests_idx[ss] > 4)
	{
                local _msg = fmt ("%s flagged as HotSubnet where as it is also Scan::Interests: %s", ip, Scan::interests_idx[ip]);
                NOTICE([$note=Conflict, $src=ip, $msg=fmt("%s", _msg)]);
        }
}
