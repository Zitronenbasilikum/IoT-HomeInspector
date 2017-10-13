# Load other scripts
# @load ...
@load base/protocols/conn/polling
@load base/protocols/conn/main

# Module Name
# module MyModule;
module ConnByteStream;

export{
	## The period of delay for all established connections
 	## before rechecking them for whatever I'm checking them for.
 	const checkup_interval = 10sec;

 	## connection data
	type MyRec: record {
		## This is the time of the first packet.
		ts: time &optional &default=double_to_time(0);
		##
		orig_ip_bytes: count &optional &default=0;
		##
		resp_ip_bytes: count &optional &default=0;
		##
		duration: interval &optional &default=0secs;
		##
		orig_p: set[port] &optional;
		##
		resp_p: set[port] &optional;
	};

	# Table of orig/resp pair and connection data
	global conn_table: table[conn_id] of MyRec;
}

event ConnByteStream::write_to_log()
 	{
 	print "Write to log..............";
 	# Write to log

 	local ip_table: table[addr,addr] of MyRec; 
 	for(id in conn_table)
	{
	# Konstrukt new table entry and initialize vars
	if( [id$orig_h, id$resp_h] !in ip_table)
		{
		ip_table[id$orig_h, id$resp_h] = MyRec();
		ip_table[id$orig_h, id$resp_h]$orig_p = set();
		ip_table[id$orig_h, id$resp_h]$resp_p = set();
		}
	
	# min ts, add bytes, max duration, add ports
	local myRec: MyRec = ip_table[id$orig_h, id$resp_h];
	
	if( myRec$ts > conn_table[id]$ts )
		{
		myRec$ts = conn_table[id]$ts;
		}
	myRec$orig_ip_bytes += conn_table[id]$orig_ip_bytes;
	myRec$resp_ip_bytes += conn_table[id]$resp_ip_bytes;
	
	if( myRec$duration < conn_table[id]$duration )
		{
		myRec$duration = conn_table[id]$duration;
		}
	
	add myRec$orig_p[id$orig_p];
	add myRec$resp_p[id$resp_p];

	# Clean up conn_table
	delete conn_table[id];

	}

	for( [orig, resp] in ip_table )
		{
		print [orig,resp];
		print ip_table[orig,resp];
		}


	# Reschedule this event.
 	schedule checkup_interval { ConnByteStream::write_to_log() };
 	}

event bro_init()
	{
	# Write to log every second
	# Schedule the event that does the check.
 	schedule checkup_interval { ConnByteStream::write_to_log() };
	}

function polling_callback(c: connection, cnt: count): interval
	{
	# Init if deleted in write_to_log	
	if( c$id !in conn_table)
		{
		conn_table[c$id] = MyRec();
		}
	
	local myRec : MyRec = conn_table[c$id];
	
	myRec$ts = c$start_time;
	myRec$orig_ip_bytes = c$orig$num_bytes_ip;
	myRec$resp_ip_bytes = c$resp$num_bytes_ip;
	myRec$duration = c$duration;	

	return checkup_interval;
	}

event connection_established(c: connection) &priority=5
	{
		# Poll every new connection
		if(c$id !in conn_table)
			{
				ConnPolling::watch(c, polling_callback,0,0secs);
				conn_table[c$id] = MyRec();
			}
	}
