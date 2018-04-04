module History;

export {

	global institutional_servers: set[addr] = { 
							128.3.120.102,	#vpn1
							128.3.120.103,	#vpn2
							128.3.41.87,	#bigfix
							131.243.60.55,	#sophosprod2
							131.243.170.3,	#appserver
							131.243.2.15,	#scrappy
							131.243.2.33,	#scooby
							131.243.228.16,	#ldap
							131.243.228.37,	#identity	
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
