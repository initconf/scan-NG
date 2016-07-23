module Scan; 

export {

	global ok_web_bots: pattern = /bot|spider\.html|baidu/ ; 
	global ok_robots: pattern = /robots\.txt/; 
} 

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=3
{

	if (ok_robots in original_URI) 
	{ 
		local orig=c$id$orig_h ; 
	    	#print fmt ("IP: %s, method: %s, original_URI: %s, unescaped_URI: %s, version: %s", orig, method, original_URI, unescaped_URI, version); 
		if (orig !in Scan::whitelist_ip_table) 
		{ 
			event Scan::m_w_add_ip(orig, fmt("web-spider seeking %s", original_URI)); 
		} 
	}
} 


# Process the response code from the server
event http_reply(c: connection, version: string, code: count, reason: string)
{

    #print fmt ("version: %s, code: %s, reason: %s", version, code, reason); 
	
} 


event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
{

	
                if ( name == "USER-AGENT" && ok_web_bots  in value )
		{ 
			#print fmt ("name: %s, value: %s", name, value);  
			local orig=c$id$orig_h ; 
			if (orig !in Scan::whitelist_ip_table) 
			{ 
				event Scan::m_w_add_ip(orig, fmt ("%s crawler is seen: %s", orig, value)); 
			} 
		} 
} 
