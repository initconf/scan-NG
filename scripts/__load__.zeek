#redef exit_only_after_terminate=T ; 

redef table_expire_interval = 0.01 secs ;
redef table_incremental_step=250 ;

@load ./debug 
@load ./site-subnets
# disabled 7/31 ; reenabled 2017-07-15  - aashish 
#@load ./conn-history 
#@load ./avoid-scan-FP.zeek 
@load ./host-profiling 
@load ./port-flux-density 



@load ./stats

@load ./scan-base 

@load ./scan-inputs    
@load ./skip-services 
@load ./scan-blocked-hotsubnets.zeek 
@load ./scan-spikes 
@load ./ss.zeek 

@load ./identify-web-spiders

@load ./check-knock 
@load ./check-backscatter
@load ./check-addressscan
#@load ./check-portscan 
@load ./check-lowporttroll
@load ./trw
@load ./check-landmine

@load ./check-scan-impl 
@load ./check-scan
@load ./scan-config 

#@load ./netcontrol-scan-rules 
#@load ./check-port-knock 

# if you need to redef Site::local_nets 
# ideally it should be built automatally
# from node.cfg but you may need to do this
# if running standalone on a pcap 

#redef Site::local_nets += {     } ;

