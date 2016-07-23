redef exit_only_after_terminate=T ; 

@load ./debug 
@load ./site-subnets
@load ./conn-history 
@load ./host-profiling 

@load ./stats
@load ./scan-base 

@load ./scan-inputs    
@load ./scan-summary 

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
@load ./netcontrol-scan-rules 

#@load ./check-port-knock 

redef Site::local_nets += {     128.3.0.0/16, 131.243.0.0/16, 192.12.173.0/24,
				192.58.231.0/24, 204.62.155.0/24, [2620:83:8000::]/48,
                               	198.128.24.0/21, 198.128.42.0/24, 198.128.192.0/19,
                               	[2620:83:8001::]/48, [2001:400:613:18::]/64,
} ;
