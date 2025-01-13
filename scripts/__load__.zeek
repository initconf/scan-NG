#v3 
#redef exit_only_after_terminate=T ;

redef global_hash_seed = "bloomhash";
redef Log::print_to_log = Log::REDIRECT_STDOUT;

@load policy/frameworks/notice/actions/drop

@load ./debug
@load ./site-subnets
@load ./host-profiling
@load ./port-flux-density

@load ./stats

@load ./scan-base
@load ./expire-known-scanners.zeek
@load ./ss.zeek
@load ./conn-history

@load ./scan-inputs
@load ./skip-services
@load ./blocked-nets.zeek
@load ./hotsubnets.zeek
@load ./scan-spikes

@load ./identify-web-spiders

@load ./check-knock
@load ./check-knocksubnet.zeek
@load ./check-backscatter
#@load ./port-address-scan.zeek
@load ./check-addressscan
@load ./check-lowporttroll
@load ./check-portscan
#@load ./port-scan
@load ./trw
@load ./check-landmine

@load ./check-scan-impl
@load ./check-scan
@load ./scan-config
@load ./interests
@load ./interest-conflict.zeek


@load ./lbl.scan-policy.zeek
#@load ./lbl.scan-policy-drop.zeek

#@load ./netcontrol-scan-rules
#@load ./check-port-knock

redef Site::local_nets += {
	128.3.0.0 / 16,
	131.243.0.0 / 16,
	192.12.173.0 / 24,
	192.58.231.0 / 24,
	204.62.155.0 / 24,
	[2620:83:8000::] / 48,
	198.128.24.0 / 21,
	198.128.42.0 / 24,
	198.128.192.0 / 19,
	[2620:83:8001::] / 48,
	[2001:400:613:18::] / 64,
};


