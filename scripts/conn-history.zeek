module History; 

@load ./debug.bro 

export {
	const DEBUG = 0 ; 

	global tcp_outgoing_SF : opaque of bloomfilter ; 
	global tcp_conn_duration_bloom : opaque of bloomfilter ;

	global blocked_scanners : opaque of bloomfilter ; 
	global ever_touched : opaque of bloomfilter ; 
	global initialized_bloom: bool = F  &persistent ; 

	redef enum Notice::Type += {
	  SF_to_Scanner, # If ever a TCP_ESTABLISHED to the potential Scanner
	  LongDuration, 
	} ; 

	global m_w_add: event (ip: addr);
	global w_m_new: event (ip: addr);
        global add_to_bloom: function(ip: addr);

	global check_conn_history: function (ip: addr): bool ; 

} 


function check_conn_history(ip: addr): bool 
{
	local result = F ; 

	local seen = bloomfilter_lookup(History::tcp_outgoing_SF, ip);

	if (seen == 1)
	{
       		NOTICE([$note=History::SF_to_Scanner, $src=ip,
       			$msg=fmt("outgoing SF to scanner %s", ip)]);
		
		result = T ; 
	}


	local duration_seen = bloomfilter_lookup(History::tcp_conn_duration_bloom, ip);

	if (duration_seen == 1)
	{
		NOTICE([$note=History::LongDuration, $src=ip,
		$msg=fmt("known long duration connections from this scanner IP: %s", ip)]);
		
		result = T ; 
	}

	return result ; 
} 

event zeek_init()
{
	# on avg we see 6.2M ip address a day 2016-04-01
	# so setting bloom to 10M 
	# not yet measured what is overlap of 6.2M the next day
	
	tcp_outgoing_SF = bloomfilter_basic_init(0.00001, 40000000);
	tcp_conn_duration_bloom= bloomfilter_basic_init(0.00001, 40000000);
	#tcp_outgoing_SF = bloomfilter_basic_init(0.0001, 400);
	#tcp_conn_duration_bloom= bloomfilter_basic_init(0.0001, 400);
	initialized_bloom = T ; 
}



#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /History::m_w_add/;
#redef Cluster::worker2manager_events += /History::w_m_new/;
#@endif

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
        {
        Broker::auto_publish(Cluster::worker_topic, History::m_w_add) ; 
        }
@else
event zeek_init()
        {
        Broker::auto_publish(Cluster::manager_topic, History::w_m_new) ; 
        }
@endif

@endif


function add_to_bloom(ip: addr)
{
	local seen = bloomfilter_lookup(tcp_outgoing_SF, ip) ; 

	if ( seen == 0 ) 
	{ 
		bloomfilter_add(tcp_outgoing_SF, ip);

@if ( Cluster::is_enabled() )
	        event History::w_m_new(ip);
        	#Scan::log_reporter(fmt ("add_to_bloom %s", ip), 0);
@endif
	} 
	
}


@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event History::w_m_new(ip: addr)
{
	#Scan::log_reporter(fmt ("History: w_m_new: %s", ip), 0);
	bloomfilter_add(tcp_outgoing_SF, ip);
}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event History::m_w_add(ip: addr)
{
	Scan::log_reporter(fmt ("History: m_w_add: %s", ip), 0);
	bloomfilter_add(tcp_outgoing_SF, ip);
}
@endif

# so that we have all the flags etc

# for flagging scanners rather quickly 
#event connection_state_remove(c: connection) &priority=-5
#

# build bloom for good guys
# good guys = IP which successfully accepted a connection 
# originating from the local_nets 

event connection_established(c: connection) &priority=-5
{
	local src = c$id$orig_h; 
	local dst = c$id$resp_h; 
		
	# ignore remote originating connections 	
	if (src !in Site::local_nets) 
		return ; 

	if (c$resp$state == TCP_ESTABLISHED)
	{ 
		add_to_bloom(dst) ; 
	} 

} 

event connection_state_remove(c: connection) &priority=-5
{
	local src = c$id$orig_h; 
	local dst = c$id$resp_h; 
		
	# ignore remote originating connections 	
	if (src !in Site::local_nets) 
		return ; 

	
	# only worry about TCP connections
        # we deal with udp and icmp scanners differently
        if (c$conn$proto == udp || c$conn$proto == icmp )
                return ;

	if (c$duration > 60 secs)
	{ 
		bloomfilter_add(tcp_conn_duration_bloom, src); 	
	} 

} 
