# Central location to set/calibrate all redef'able variables for scan-detection
# This saves users effort to locate specific knobs deep inside heuristics
# Modify these as you see fit
# Presently left as standard defaults

module Scan;

redef Scan::activate_SubnetKnock = T;
redef Scan::activate_KnockKnockScan = T;
redef Scan::activate_Backscatter = T;
redef Scan::activate_LandMine = T;
redef Scan::activate_LowPortTrolling = T;
redef Scan::activate_AddressScan = T;
redef Scan::activate_PortScan = T;
redef TRW::use_TRW_algorithm = F;

## Important to configure for Landmine detection
#  if subnet_feed is empty then LandMine detection wont work

redef Scan::landmine_thresh_trigger = 5 &redef;
redef Scan::landmine_ignore_ports: set[port] = {
	53/tcp,
	53/udp,
	1094/tcp,
	1095/tcp,

};

redef Scan::allow_icmp_landmine_check = F;
redef Scan::ignore_landmine_ports: set[port] = {
	8/icmp
} &redef;

# 8/icmp as d_port == backscatter from DoS

## this is list of allocated subnets in your network
## landmine works on watching connections which are not in allocated subnets
## file looks as follows (tab seperated)
# 	Example
#	#fields Network Gateway Enclaves        Use
#	128.3.2.0/24    128.3.2.1       LBL     Research group

@ifndef ( Scan::subnet_feed )
@load ./site-subnets.zeek
@endif

redef Scan::subnet_feed = "/YURT/feeds/BRO-feeds/LBL-subnets.csv-LATEST_BRO";

################
## Input files - Whitelist IP and Subnets file
# 	Example Header and 1st row - whitelist.scan
#	#fields ip      comment
#	1.2.1.1       	a scanning ip addres
# 	Example Header and 1st row - subnet-whitelist.scan
#	#fields nets    comment
#	15.5.5.5/32     NO scanning from EDU
################

#redef Scan::whitelist_ip_file = "/YURT/feeds/BRO-feeds/ip-whitelist.scan" ;
#redef Scan::whitelist_subnet_file = "/YURT/feeds/BRO-feeds/subnet-whitelist.scan" ;

## KnockKnockScan whitelist file
#	File to whitelist known hosts and services in order to prevent
# 	FP due to sticky configurations of hosts/Laptops which move around
#	Example header and 1st row :
#	#fields exclude_ip      exclude_port    t       comment
#	11.3.2.5  123	tcp     example comment

redef ipportexclude_file = "/YURT/feeds/BRO-feeds/knockknock.exceptions";

################
### scan-summary.bro config
# Scan-summary: if T will enable generation of scan-summary.log which tracks
# start_time, end_time, detect_time of a scan
# duration of scan
# host many total connections scanner made
# how many total uniq hosts did the scanner attempted/connected to
# GeoIP location of the scanner
# what Heuristic caught this scanner
# detection latency
# This is a slightly expensive to run policy in terms of increase in worker2manager events
################

redef enable_scan_summary = T;

################
## KnockKnockScan specific configurations
# These are KnockKnockScan Specific tweaks only. These don't affect any other heuristics
# sensitive and sticky config ports
################

redef Scan::knock_medium_threshold_ports += {
	17500/tcp, # dropbox-lan-sync
	135/tcp,
	139/tcp,
	445/tcp,
	0/tcp,
	389/tcp,
	88/tcp,
	3268/tcp,
	9200/tcp,
};

redef Scan::knock_high_threshold_ports += {
	53/tcp,
	861/tcp,
	80/tcp,
	443/tcp,
	8080/tcp,
	113/tcp,
	636/tcp,
	135/tcp,
	139/tcp,
	17500/tcp,
	18457/tcp,
	3268/tcp,
	3389/tcp,
	3832/tcp,
	389/tcp,
	4242/tcp,
	445/tcp,
	52311/tcp,
	5900/tcp,
	60244/tcp,
	60697/tcp,
	7000/tcp,
	7680/tcp,
	8192/tcp,
	8194/tcp,
	8443/tcp,
	88/tcp,
	9001/tcp,
	1095/tcp,
	1094/tcp,
};

################
## AddressScan
################

redef Scan::shut_down_thresh = 100;
redef Scan::suppress_UDP_scan_checks = T;

################
### These affect the entire scan detection ######
################

# skip

redef Scan::portexclude_file = "/YURT/feeds/BRO-feeds/scan-portexclude";

redef skip_outbound_services += {
	#22/tcp,
	3128/tcp,
	80/tcp,
	8080/tcp,
};

redef skip_scan_sources += {
	255.255.255.255, # who knows why we see these, but we do
};

redef skip_scan_nets += { };

# List of well known local server/ports to exclude for scanning
# purposes.

redef skip_dest_server_ports += { };

redef Scan::skip_services -= {
	1/tcp,
	11/tcp,
	15/tcp,
	19/tcp,
	25/tcp,
	42/tcp,
	53/tcp,
	80/tcp,
	87/tcp,
	109/tcp,
	110/tcp,
	111/tcp,
	135/tcp,
	137/tcp,
	138/tcp,
	139/tcp,
	143/tcp,
	407/tcp,
	443/tcp,
	445/tcp,
	513/tcp,
	514/tcp,
	520/tcp,
	540/tcp,
	631/tcp,
	8194/tcp,
};

#redef Scan::skip_services += { 2323/tcp, 23/tcp, 445/tcp};
#redef Scan::skip_services += { 123/tcp, } ;
#redef Scan::skip_services += { 111/tcp, } ;
#redef Scan::skip_services += { 7547/tcp, 5555/tcp } ;

# Dont flag internal hosts hitting external IPs on following ports
# affects entire Scan Detection

redef Scan::skip_outbound_services += {
	#22/tcp,
	3128/tcp,
	80/tcp,
	8080/tcp,
};
redef Scan::skip_scan_sources += {
	255.255.255.255, # who knows why we see these, but we do
} &redef;

redef Scan::skip_scan_nets += { };

# List of well known local server/ports to exclude for scanning purposes.
redef Scan::skip_dest_server_ports: set[addr, port] += {
	[131.243.60.26, 52311/tcp], #bigfix-dmzrelay.lbl.gov
	[131.243.60.49, 52311/tcp], #bigfix-masterrelay.lbl.gov
	[128.3.41.23, 52311/tcp], #bigfix-relay1.lbl.gov
	[131.243.60.51, 52311/tcp], #bigfix-relay2.lbl.gov
	[128.3.41.87, 52311/tcp], #bigfix.lbl.gov
};

redef Scan::never_drop_nets += {
	Site::neighbor_nets
};
redef can_drop_connectivity = T;
redef dont_drop_locals = T &redef;

event zeek_done()
{
#print fmt ("high thresh ports: %s", Scan::knock_high_threshold_ports);
#print fmt ("medium thresh ports: %s", Scan::knock_medium_threshold_ports);
}
