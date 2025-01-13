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


#@load ./lbl.scan-policy.zeek
#@load ./lbl.scan-policy-drop.zeek

#@load ./netcontrol-scan-rules
#@load ./check-port-knock



