# This policy tries to identify #of uniq scanners for a given port
# and if #scanners for a port crosses a threshold, it generates a notice
# basically, we want to find sudden spikes in scanning
# esp with botnets such as mirai etc. 

module Scan ;

export {

	redef enum Notice::Type += {
                Spike, 
	} ; 
	global uniq_scanners_on_port_threshold : vector of count = { 10, 20, 30, 10000, 25000, 50000, 100000, 150000, 200000, 300000, 5000000}  ;
 	global check_scanners_threshold: function (v: vector of count, idx: table[port] of count, service: port, n: count):bool ;

	global port_spike_idx: table[port] of count &default= 0 &create_expire=7 days ; 	
	global port_spikes: table[port] of set[addr] &create_expire=10 hrs ;  
	global check_port_spikes: function(orig: addr, service: port); 
} 

function check_scanners_threshold (v: vector of count, idx: table[port] of count, service: port, n: count):bool
{
#print fmt ("service: %s and IDX_service: %s and n is: %s and v[idx[service]] is: %s", service, idx[service], n, v[idx[service]]);

         if ( idx[service] < |v| && n >= v[idx[service]] )
                {
                ++idx[service];

                return (T);
                }
        else
                return (F);
}


function check_port_spikes(orig: addr, service: port)
{
	

	if (service !in port_spikes)
	{ 
		local a=set(); 
		port_spikes[service] = a ; 
	} 

	if (orig !in port_spikes[service])
		add port_spikes[service] [orig] ; 
	
	local t = check_scanners_threshold(uniq_scanners_on_port_threshold, port_spike_idx, service, |port_spikes[service]|); 
	if (t)
	{ 
		local _msg = fmt ("Spike on scanning of port %s with %s IPs", service, |port_spikes[service]|); 
		NOTICE([$note=Spike, $src=orig, $p=service, $msg=fmt("%s", _msg)]);
	} 
} 
