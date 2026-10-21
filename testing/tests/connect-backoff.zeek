# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT 2>zeek-stderr | sort > out
# @TEST-EXEC: grep -c 'Failed to connect' zeek-stderr > connect-errors
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff connect-errors
#
# @TEST-DOC: Without a server, writers drop writes and only one connection attempt is made within the initial backoff.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::url = "nats://127.0.0.1:1";
redef LogNATS::dropped_writes_log = 0;

# Send writes to the writer threads right away so they're
# dropped before metrics are collected in zeek_done().
redef Log::write_buffer_size = 1;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	}

event zeek_done()
	{
	sleep(100msec);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
