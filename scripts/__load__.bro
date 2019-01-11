redef exit_only_after_terminate=T ; 

redef table_expire_interval = 0.1 secs ;
redef table_incremental_step=250 ;

@load ./debug 
@load ./site-subnets
### disabled 7/31 ; reenabled 2017-07-15  - aashish 
#@load ./conn-history 
#@load ./avoid-scan-FP.bro 
@load ./host-profiling 


@load ./stats

@load ./scan-base 

@load ./scan-inputs    
@load ./skip-services 
@load ./scan-spikes 
#########@load ./scan-summary 
@load ./ss.bro 

@load ./identify-web-spiders

@load ./check-knock 
@load ./check-backscatter
@load ./check-landmine
@load ./check-addressscan
#@load ./check-portscan 
@load ./check-lowporttroll
@load ./trw

@load ./check-scan-impl 
@load ./check-scan
@load ./scan-config 
#@load ./netcontrol-scan-rules 


### define your local_nets here and define all variables in  scan-config.bro 
#redef Site::local_nets += {     } ;

