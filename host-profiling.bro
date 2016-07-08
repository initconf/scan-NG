module Site; 

export {

	# table to maintain list of all active hosts in local_nets with open ports
        global host_profiles: table [addr] of set[port] &read_expire=2 days ;

	global Site::w_m_new_host_profile: event(cid: conn_id); 
	global Site::m_w_add_host_profiles: event (cid: conn_id); 

	redef enum Log::ID += { host_open_ports_LOG};

       	type Info: record {
                # When the email was seen.
                ts:   time    &log;
		#id: conn_id &log ; 
                host: addr &log &optional ;
                d_port:  port &log &optional;
		peer: string &log &optional ; 
                #services: string &log &optional;
        };

} 


event bro_init() &priority=5
{
        Log::create_stream(Site::host_open_ports_LOG, [$columns=Info]);

} 

function log_host_profiles(cid: conn_id) 
{
                local info: Info;

                info$ts = network_time(); 
                #info$id = cid ;
                info$host= cid$resp_h;
                info$d_port= cid$resp_p ; 
		#info$services = "" ; 
		
                #for (s in host_profiles[cid$resp_h])
		#{
                #        info$services += fmt (" %s ", s);
		#	#print fmt ("service is %s %s", cid$resp_h, s); 
		#} 

		info$peer = peer_description; 
                Log::write(Site::host_open_ports_LOG, info);

}


@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Site::m_w_add_host_profiles/;
redef Cluster::worker2manager_events += /Site::w_m_new_host_profile/;
@endif


	
function add_to_host_profile_cache(cid: conn_id)
{
	local orig = cid$orig_h ;
	local resp = cid$resp_h ;
	local d_port = cid$resp_p; 
	
	if (orig in Site::local_nets)
		return ; 

	 if (resp !in host_profiles)
                host_profiles[resp]=set();

        if (d_port !in host_profiles[resp])
        {
        	#Scan::log_reporter(fmt ("add_to_host_profile_cache %s", cid));
                add host_profiles[resp][d_port] ;

                local _services="" ;
                for (s in host_profiles[resp])
                        _services += fmt (" %s ", s);
                #print fmt ("%s has services on %s", resp, _services) ;


@if ( Cluster::is_enabled() )
        event Site::w_m_new_host_profile(cid);
@endif
        }
}


@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event Site::w_m_new_host_profile(cid: conn_id)
{
        local orig = cid$orig_h ;
        local resp = cid$resp_h ;
        local d_port = cid$resp_p;

	##Scan::log_reporter(fmt ("w_m_new_host_profile: %s", cid));

	if (resp !in host_profiles)
		host_profiles[resp]=set();

	if (d_port !in host_profiles[resp])
	{
		add host_profiles[resp][d_port] ;
		log_host_profiles(cid); 
	} 
	event Site::m_w_add_host_profiles(cid);
}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Site::m_w_add_host_profiles(cid: conn_id)
{
        local orig = cid$orig_h ;
        local resp = cid$resp_h ;
        local d_port = cid$resp_p;

	###Scan::log_reporter(fmt ("m_w_add_host_profiles: %s", cid));

	if (resp !in host_profiles)
		host_profiles[resp]=set();

	if (d_port !in host_profiles[resp])
	{
		add host_profiles[resp][d_port] ;
	} 
}
@endif



event connection_established(c: connection)
{
        local orig = c$id$orig_h ;
        local resp = c$id$resp_h ;
        local d_port = c$id$resp_p ;

        ### if outgoing traffic, exit
        if (Site::is_local_addr(resp))
	{ 
		add_to_host_profile_cache(c$id); 
	} 
}
