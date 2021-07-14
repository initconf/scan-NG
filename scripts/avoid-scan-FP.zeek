module History;

export {

	global institutional_servers: set[addr] = { 

						};
} 

event connection_established (c: connection)
{

	local orig = c$id$orig_h ; 
	local resp = c$id$resp_h ; 

	if (resp !in Site::local_nets)
		return ; 
	
	if (resp in institutional_servers) 
		add_to_bloom(orig); 
} 
