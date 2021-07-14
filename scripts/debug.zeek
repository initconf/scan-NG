module Scan; 


export {
	const DEBUG = 1; 

	global  log_reporter: function (msg: string, debug: count);
} 




function  log_reporter(msg: string, debug: count)
{
	
        event reporter_info(network_time(), msg, peer_description);
        if (debug > 20 ) {
                event reporter_info(network_time(), msg, peer_description);
        }


        if (DEBUG >= 25) 
	{
	@if ( ! Cluster::is_enabled())
		print fmt("%s", msg);
	@endif
        event reporter_info(network_time(), msg, peer_description);
        }
}

