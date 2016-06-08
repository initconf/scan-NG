module Scan; 

redef Scan::activate_KnockKnockScan = T ;
redef Scan::activate_BackscatterSeen = T ;
redef Scan::activate_LandMine = T ;
redef Scan::activate_LowPortTrolling = T ;
redef Scan::activate_PortScan = T  ;
redef Scan::activate_AddressScan =  ;
redef TRW::use_TRW_algorithm = F ;


#### these are KnockKnockScan Specific tweaks only. These don't affect any other detection heuristics
# sensitive and sticky config ports

redef Scan::high_threshold_ports += { 861/tcp, 80/tcp, 443/tcp, 8443/tcp, 8080/tcp } &redef ;

redef Scan::medium_threshold_ports: set[port] += {
						17500/tcp,  # dropbox-lan-sync
						135/tcp, 139/tcp, 445/tcp,
						0/tcp, 389/tcp, 88/tcp,
						3268/tcp, 52311/tcp,
					    } ; 

redef Scan::high_threshold_ports += { 113/tcp, 636/tcp, 135/tcp, 139/tcp, 17500/tcp, 18457/tcp,
				3268/tcp, 3389/tcp, 3832/tcp, 389/tcp,
				4242/tcp, 443/tcp, 445/tcp, 52311/tcp, 5900/tcp,
				60244/tcp, 60697/tcp, 80/tcp, 8080/tcp, 7000/tcp, 8192/tcp,
				8194/tcp, 8443/tcp, 88/tcp, 9001/tcp,
				};



### what qualifies to be checked for scanner 
### skip the following as since already blocked on border 

redef Scan::skip_services += { 1/tcp, 11/tcp, 15/tcp, 19/tcp, ## 23/tcp, 
				25/tcp, 42/tcp, 53/tcp, 80/tcp, 
				87/tcp, 109/tcp, 110/tcp, 111/tcp, 
				135/tcp, 137/tcp, 138/tcp, 139/tcp, 
				143/tcp, 407/tcp, 443/tcp, 445/tcp, 
				513/tcp, 514/tcp, 520/tcp, 540/tcp, 
				631/tcp,
                       };


redef Scan::skip_services += { 123/tcp, } ;
redef Scan::skip_services += { 111/tcp, } ; 
redef Scan::skip_outbound_services += { 22/tcp, 3128/tcp, 80/tcp, 8080/tcp, } ; 
redef Scan::skip_scan_sources += {
	255.255.255.255,        # who knows why we see these, but we do
        } &redef;

redef Scan::skip_scan_nets  += {} ; 



# List of well known local server/ports to exclude for scanning purposes.
redef Scan::skip_dest_server_ports: set[addr, port] += {} ; 



######### AddressScan 

redef Scan::shut_down_thresh  = 100 ; 


########## Landmine configs
redef Scan::landmine_thresh_trigger = 5 &redef;
redef Scan::ignore_src_ports: set [port] = { 53/tcp, 53/udp} ;

##### this is list of allocated subnets in your network
##### landmine works on watching connections which are not in allocated subnets 
##### file looks as follows (tab seperated) 
##### #fields Network Gateway Enclaves        Use
##### 128.3.2.0/24    128.3.2.1       LBL     Building 50B: Comp Directorate/Physics/Library, floors 4+5+6

@ifndef(Site::subnet_feed)
@load site-subnets.bro
@endif 

redef Site::subnet_feed="/YURT/feeds/BRO-feeds/LBL-subnets.csv-LATEST_BRO" ; 
