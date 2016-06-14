module Scan; 

export {

	global gather_statistics = T &redef ;

	type scan_counters: record { 
		new_conn_counter: count &log &default=0 ;
		is_catch_release_active: count &log &default=0 ;
		known_scanners_counter: count &log &default=0 ;
		not_scanner: count &log &default=0 ;
		darknet_counter	: count &log &default=0 ;
		not_darknet_counter	: count &log &default=0 ;
		already_scanner_counter : count &log &default=0 ;
		validation_entry : count &log &default=0 ;
		validation_success: count &log &default=0 ;

		
		c_knock_validate: count &log &default=0 ;
		c_knock_checkscan: count &log &default=0 ;
		c_knock_core: count &log &default=0 ;
		
		c_land_validate: count &log &default=0 ;
		c_land_checkscan: count &log &default=0 ;
		c_land_core: count &log &default=0 ;

		c_backscat_validate: count &log &default=0 ;
		c_backscat_checkscan: count &log &default=0 ;
		c_backscat_core: count &log &default=0 ;

		c_addressscan_validate: count &log &default=0 ;
		c_addressscan_checkscan: count &log &default=0 ;
		c_addressscan_core: count &log &default=0 ;

		check_scan_counter: count &log &default=0 ;
	
		worker_to_manager_counter: count &log &default=0 ;
		run_scan_detection: count &log &default=0 ;
		check_scan_cache: count &log &default=0 ;

		event_peer: string &log &optional ; 
	}; 
	

	global worker_count  = 0 ; 

	global stat_freq = 10 mins ; 
	global s_counters : scan_counters ; 

	global aggregate_workers: table[string] of bool &default=F ; 

	global Scan::m_w_send_performance_counters: event( send: bool); 
	global Scan::w_m_update_performance_counters: event(sc: scan_counters); 


}  

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || (! Cluster::is_enabled()) )
event dump_stats()
{
	#log_reporter(fmt ("dump_stats calling send_perf_counters: %s", s_counters ),0); 
	event Scan::m_w_send_performance_counters(T); 

	schedule stat_freq { dump_stats() }; 	
} 


event bro_init()
{
	if (gather_statistics)
		schedule stat_freq { dump_stats() }; 	

} 


@endif 


@if (  Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Scan::m_w_send_performance_counters/ ;
redef Cluster::worker2manager_events += /Scan::w_m_update_performance_counters/ ;
@endif


@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (! Cluster::is_enabled()) )

event Scan::m_w_send_performance_counters(send: bool)
{
	worker_count = 0 ; 
	#log_reporter(fmt ("m_w_send_performance_counters calling w_m_update_performance_counters" ),0); 
	event Scan::w_m_update_performance_counters(s_counters); 
}

@endif 

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || (! Cluster::is_enabled()) )

event Scan::w_m_update_performance_counters(sc: scan_counters)
{
	#log_reporter(fmt ("inside w_m_update_performance_counters : %s", sc),0); 
	#log_reporter(fmt("Got counters: %s", sc),0); 

	

	######### aggregate the numbers now 
		s_counters$new_conn_counter += sc$new_conn_counter ; 
		s_counters$is_catch_release_active += sc$is_catch_release_active ; 
		s_counters$known_scanners_counter += sc$known_scanners_counter ; 
		s_counters$not_scanner += 	sc$not_scanner ; 
		s_counters$darknet_counter	 += sc$darknet_counter ; 
		s_counters$not_darknet_counter	 += sc$not_darknet_counter ; 
		s_counters$already_scanner_counter  += sc$already_scanner_counter ; 
		s_counters$validation_entry  += sc$validation_entry  ; 
		s_counters$validation_success += sc$validation_success ; 
		s_counters$c_knock_validate += sc$c_knock_validate ; 
		s_counters$c_knock_checkscan += sc$c_knock_checkscan  ; 
		s_counters$c_knock_core += sc$c_knock_core ; 
		s_counters$c_land_validate += sc$c_land_validate ; 
		s_counters$c_land_checkscan += 	sc$c_land_checkscan ; 
		s_counters$c_land_core += sc$c_land_core  ; 
		s_counters$c_backscat_validate += sc$c_backscat_validate ; 
		s_counters$c_backscat_checkscan += sc$c_backscat_checkscan ; 
		s_counters$c_backscat_core += sc$c_backscat_core ; 
		s_counters$c_addressscan_validate += sc$c_addressscan_validate ; 
		s_counters$c_addressscan_checkscan += sc$c_addressscan_checkscan ; 
		s_counters$c_addressscan_core += sc$c_addressscan_core  ; 
		s_counters$check_scan_counter += sc$check_scan_counter  ; 
		s_counters$worker_to_manager_counter += sc$worker_to_manager_counter ; 
		s_counters$run_scan_detection += sc$run_scan_detection  ; 
		s_counters$check_scan_cache += sc$check_scan_cache ; 


			local c_worker = sc$event_peer ; 

			if (c_worker !in aggregate_workers) 
				aggregate_workers[c_worker]= T ; 


	if (|aggregate_workers| == Cluster::worker_count ) 
	{
		#log_reporter(fmt("STATISTICS: %s", s_counters),0); 
	
		### reset the worker reporting table again 
		for (w in aggregate_workers) 
			delete aggregate_workers[w] ; 
		
		s_counters$new_conn_counter  = 0 ; 
                s_counters$is_catch_release_active  = 0 ; 
                s_counters$known_scanners_counter  = 0 ; 
                s_counters$not_scanner  = 0 ; 
                s_counters$darknet_counter        = 0 ; 
                s_counters$not_darknet_counter    = 0 ; 
                s_counters$already_scanner_counter   = 0 ; 
                s_counters$validation_entry   = 0 ; 
                s_counters$validation_success  = 0 ; 

                s_counters$c_knock_validate  = 0 ; 
                s_counters$c_land_validate  = 0 ; 
                s_counters$c_backscat_validate  = 0 ; 
                s_counters$c_addressscan_validate  = 0 ; 

                s_counters$check_scan_counter  = 0 ; 
                s_counters$check_scan_cache  = 0 ; 


		### since these are manager counters we don't zero these 
		### s_counters$worker_to_manager_counter  = 0 ; 
		### s_counters$run_scan_detection  = 0 ; 
                ### s_counters$c_knock_checkscan  = 0 ; 
                ### s_counters$c_knock_core  = 0 ; 
                ### s_counters$c_land_checkscan  = 0 ; 
                ### s_counters$c_land_core  = 0 ; 
                ### s_counters$c_backscat_checkscan  = 0 ; 
                ### s_counters$c_backscat_core  = 0 ; 
                ### s_counters$c_addressscan_checkscan  = 0 ; 
                ### s_counters$c_addressscan_core  = 0 ; 

		### reset worker counts 
		worker_count = 0 ; 

	} 

} 

@endif 




