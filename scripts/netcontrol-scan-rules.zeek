module NetControl;

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )

event NetControl::rule_expire(r: Rule, p: PluginState) &priority=-5
{
	local ip = subnet_to_addr(r$entity$ip);
#Scan::log_reporter(fmt ("acld_rule_expire: Rule: %s", subnet_to_addr(r$entity$ip)),1); 
}

event NetControl::catch_release_forgotten(a: addr, bi: BlockInfo)
{
	#Scan::log_reporter(fmt("netcontrol: catoch_release_forgotten: %s: %s", a, bi),0);

	# re-enabling scan-detection once netcontrol block is removed
	if ( a in Scan::known_scanners ) {
		Scan::known_scanners[a]$status = F;
		# send the status to all workers ;
		event Scan::m_w_update_scanner(a, F);
		Scan::log_reporter(fmt(
		    "netcontro: catch_release_forgotten: m_w_update_scanner: F %s", a), 1);
	} else
		Scan::log_reporter(fmt("netcontro: IP !in known_scanners: %s", a), 1);
}

event NetControl::rule_added(r: Rule, p: PluginState, msg: string &default="")
    &priority=5
{
	local ip = subnet_to_addr(r$entity$ip);
	#event Scan::m_w_send_known_scan_stats(ip, T); 
	#Scan::log_reporter(fmt ("netcontro: m_w_send_known_scan_stats: %s", subnet_to_addr(r$entity$ip)),1);
	Scan::log_reporter(fmt("acld_rule_added: Rule: %s, %s", subnet_to_addr(
	    r$entity$ip), r), 1);

	if ( /Re-drop/ in r$location ) {
		Scan::log_reporter(fmt("netcontrol: event rule_added: %s, %s", ip, r), 1);
		Scan::known_scanners[ip]$status = T;
		# send the status to all workers ;
		event Scan::m_w_update_scanner(ip, T);
	}
}

event NetControl::rule_removed(r: Rule, p: PluginState, msg: string &default="")
    &priority=-5
{
	local ip = subnet_to_addr(r$entity$ip);

	Scan::log_reporter(fmt("acld_rule_removed: Rule: %s, %s", subnet_to_addr(
	    r$entity$ip), r), 1);

# no need to send this - we piggyback on m_w_update_scanner 
# event Scan::m_w_send_scan_summary_stats(ip, T); 
#	Scan::log_reporter(fmt ("netcontro: acld_remove: m_w_send_known_scan_stats: %s", subnet_to_addr(r$entity$ip)),1);

# re-enabling scan-detection once netcontrol block is removed 
#	if (ip in Scan::known_scanners) 
#	{ 	
#		Scan::known_scanners[ip]$status = F ; 
#		# send the status to all workers ;  
#		event Scan::m_w_update_scanner(ip, F ); 
#		Scan::log_reporter(fmt ("netcontro: event m_w_update_scanner: F %s", ip),1);
#	} 
#	else 	
#		Scan::log_reporter(fmt ("netcontro: IP !in known_scanners: %s", ip),1) ; 
}

event NetControl::rule_timeout(r: Rule, i: FlowInfo, p: PluginState)
    &priority=-5
{
	local ip = subnet_to_addr(r$entity$ip);
	Scan::log_reporter(fmt("acld_rule_timeout: Rule: %s, %s", subnet_to_addr(
	    r$entity$ip), r), 1);
}

@endif
#event NetControl::acld_rule_added(id: count, r: Rule, msg: string)
#{
#	Scan::log_reporter(fmt ("acld_rule_removed: id: %s, Rule: %s", id, r$entity$ip),0); 
#}
# 
#event NetControl::acld_rule_removed(id: count, r: Rule, msg: string)
#{
#	Scan::log_reporter(fmt ("acld_rule_removed: id: %s, Rule: %s", id, r$entity$ip),0); 
#}
#        
#event NetControl::acld_rule_error(id: count, r: Rule, msg: string)
#{
#	Scan::log_reporter(fmt ("acld_rule_removed: id: %s, Rule: %s", id, r$entity$ip),0); 
#}
