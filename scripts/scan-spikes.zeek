# This policy tries to identify #of uniq scanners for a given port
# and if #scanners for a port crosses a threshold, it generates a notice
# basically, we want to find sudden spikes in scanning
# esp with botnets such as mirai etc.

module Scan;

export {
	redef enum Notice::Type += {
		Spike,
	};
	global uniq_scanners_on_port_threshold: vector of count = {
		10,
		20,
		30,
		50,
		100,
		250,
		500,
		1000,
		2500,
		5000,
		10000,
		25000,
		50000,
		100000,
		150000,
		200000,
		300000,
		5000000
	};
	global check_scanners_threshold: function(v: vector of count, idx: table[port] of count,
	    service: port, n: count): bool;

	global port_spike_idx: table[port] of count &default=0 &create_expire=7 days;
	global port_spikes: table[port] of set[addr] &create_expire=10 hrs;

	global Scan::track_port_spikes: event(service: port, scanner: addr);

	global Scan::PortSpike : event(service: port, scanner: addr);
}

event Scan::PortSpike (service: port, scanner: addr)
{
	local u=fmt("%s",service);

	@if ( Cluster::is_enabled() )
                Broker::publish(Cluster::manager_topic, Scan::track_port_spikes, service, scanner);
        @else
                event Scan::track_port_spikes(service, scanner);
        @endif
}

function check_scanners_threshold(v: vector of count, idx: table[port] of count,
    service: port, n: count): bool
{
	if ( idx[service] < |v| && n >= v[idx[service]] ) {
		++idx[service];

		return ( T );
	} else
		return ( F );
}

event Scan::track_port_spikes(service: port, scanner: addr)
{
	if ( service !in port_spikes ) {
		local a: set[addr];
		port_spikes[service] = a;
	}

	if ( scanner !in port_spikes[service] )
		add port_spikes[service][scanner];

	local n = |port_spikes[service]|;

	local t = check_scanners_threshold(uniq_scanners_on_port_threshold,
	    port_spike_idx, service, n);
	if ( t ) {
		local _msg = fmt("Spike on scanning of port %s with %s IPs", service,
		    |port_spikes[service]|);
		NOTICE([$note=Spike, $src=scanner, $n=n, $p=service, $msg=fmt("%s", _msg)]);
	}
}
