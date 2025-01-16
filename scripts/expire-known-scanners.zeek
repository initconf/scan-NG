module Scan;

export {

 redef enum Notice::Type += {
	Removed,
	NotRemoved,
};

}

event Scan::known_scanner_remove( idx: addr, bi: NetControl::BlockInfo)
{
	local _msg = "";

	if ( idx in Scan::known_scanners)
	{
		delete Scan::known_scanners[idx] ;
		_msg = fmt ("%s is removed from known_scanners on [%s] %s. Total known_scanners: %s", idx, bi, peer_description, |Scan::known_scanners|);

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::PROXY ) || ( ! Cluster::is_enabled() ) )
		NOTICE([$note=Scan::Removed, $src=idx, $msg=fmt("%s", _msg)]);
@endif
	}
# not needed
#	else
#	{
#		_msg = fmt ("%s is not in scan::known_scanners: %s", idx, peer_description) ;
#		NOTICE([$note=Scan::NotRemoved, $src=idx, $msg=fmt("%s", _msg)]);
#	}

}


event NetControl::catch_release_forgotten(idx: addr, bi: NetControl::BlockInfo)
{
	Broker::publish(Cluster::worker_topic, Scan::known_scanner_remove, idx, bi);
	Broker::publish(Cluster::proxy_topic, Scan::known_scanner_remove, idx, bi);
}
