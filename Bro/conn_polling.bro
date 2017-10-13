# Load other scripts
# @load ...
@load base/protocols/conn/polling
#@load base/protocols/conn/main

# Module Name
# module MyModule;
module ConnByteStream;

export{
	## The period of delay for all established connections
 	## before rechecking them for whatever I'm checking them for.
 	const checkup_interval = 10sec;

	# Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

 	## connection data
	type MyRec: record {
		## Log index
		index: count &optional &default=0 &log;
		##
		checkup_interval: interval &default=checkup_interval &log;
		## This is the time of the first packet.
		ts: time &optional &default=double_to_time(0) &log;
		##
		orig_h: addr &optional &log;
		##
		resp_h:addr &optional &log;
		##
		orig_ip_bytes: count &optional &default=0 &log;
		##
		resp_ip_bytes: count &optional &default=0 &log;
		##
		duration: time &optional &default=double_to_time(0) &log;
		##
		orig_p: set[port] &optional &log;
		##
		resp_p: set[port] &optional &log;
	};

	## Index of every connection summary for better readability
	global index: count = 0;
	## Table of orig/resp pair and connection data
	global conn_table: table[conn_id] of MyRec;
}

function summarize_connections():  table[addr,addr] of MyRec
	{
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
		

		local myRec: MyRec = ip_table[id$orig_h, id$resp_h];
		# index
		myRec$index = index;
		# min ts
		if( myRec$ts > conn_table[id]$ts || myRec$ts==0 )
			{
			myRec$ts = conn_table[id]$ts;
			}
		# bytes
		myRec$orig_ip_bytes += conn_table[id]$orig_ip_bytes;
		myRec$resp_ip_bytes += conn_table[id]$resp_ip_bytes;
		# max duration
		if( myRec$duration < conn_table[id]$duration )
			{
			myRec$duration = conn_table[id]$duration;
			}
		# ip and ports
		myRec$orig_h = id$orig_h;
		add myRec$orig_p[id$orig_p];
		myRec$resp_h = id$resp_h;
		add myRec$resp_p[id$resp_p];

		# Clean up conn table
		delete conn_table[id];
		}

	return ip_table;
	}

event ConnByteStream::write_to_log()
 	{
 	# Summarize connection of IP pair
 	local ip_table: table[addr,addr] of MyRec; 
 	ip_table = ConnByteStream::summarize_connections();

	# Write to log
	for( [orig, resp] in ip_table )
		{
		Log::write(ConnByteStream::LOG, ip_table[orig,resp]);
		}

	# Set new index; and reset
	if( index < 100)
		{
		index += 1;
		}
	else
		{
		index=0;
		}
	
	# Reschedule this event.
 	schedule checkup_interval { ConnByteStream::write_to_log() };
 	}

event bro_init() &priority=5
	{
	# Create the stream. This adds a default filter automatically.
    Log::create_stream(ConnByteStream::LOG, [$columns=MyRec, $path="conn_polling"]);

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
	myRec$duration = double_to_time(0) + c$duration;	

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
