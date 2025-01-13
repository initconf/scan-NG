module Scan;

export {
	redef enum Notice::Type += {
		ScanSpike,
	};

	#global concurrent_scanners_per_port: table[port] of set[addr] &write_expire=6 hrs ;

	global concurrent_scanners_per_port: table[port] of opaque of cardinality
	    &default=function(n: any): opaque of cardinality {
		return hll_cardinality_init(0.1, 0.99);
	} &create_expire=100 days;

	global flux_density_idx: table[port] of count &create_expire=7 days;
	global flux_density_threshold: vector of count = {
		50,
		100,
		250,
		25000,
		50000,
		75000,
		100000,
		200000,
		250000
	};

	global check_flux_density_threshold: function(v: vector of count, idx: table[port] of count,
	    orig: port, n: count): bool;

	global check_port_flux_density: function(p: port, a: addr): count;
}

function check_flux_density_threshold(v: vector of count, idx: table[port] of count,
    orig: port, n: count): bool
{
	if ( orig !in idx )
		idx[orig] = 0;
	# print fmt ("orig: %s and IDX_orig: %s and n is: %s and v[idx[orig]] is: %s", orig, idx[orig], n, v[idx[orig]]);

	if ( idx[orig] < |v| && n >= v[idx[orig]] ) {
		++idx[orig];

		return ( T );
	} else
		return ( F );
}

function check_port_flux_density(d_port: port, ip: addr): count
{
	if ( ip in Site::local_nets )
		return 0;

	if ( d_port !in concurrent_scanners_per_port ) {
		local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99);
		concurrent_scanners_per_port[d_port] = cp;
	}

	hll_cardinality_add(concurrent_scanners_per_port[d_port], ip);

	local d_val = double_to_count(hll_cardinality_estimate(
	    concurrent_scanners_per_port[d_port]));

	local result = check_flux_density_threshold(flux_density_threshold,
	    flux_density_idx, d_port, d_val);

	if ( result ) {
		local msg = fmt("%s has huge spike with %s uniq scanners", d_port, d_val);
		#print fmt ("%s", msg); 
		#NOTICE([$note=ScanSpike, $p=d_port, $src_peer=get_event_peer()$descr, $msg=msg]);
		#NOTICE([$note=ScanSpike, $n=d_val, $p=d_port, $msg=msg]);

	}

	return d_val;
}
