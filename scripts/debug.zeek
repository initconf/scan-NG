module Scan;

export {
	const DEBUG = 1;

	redef Site::local_nets += {
		128.3.0.0 / 16,
		131.243.0.0 / 16
	};
	global log_reporter: function(msg: string, debug: count);
}

function log_reporter(msg: string, debug: count)
{
	if ( DEBUG >= 0 ) {
@if ( ! Cluster::is_enabled() )
		print fmt("%s", msg);
@endif
		event reporter_info(network_time(), msg, peer_description);
	}
}
