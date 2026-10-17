# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT > out
# @TEST-EXEC: nats stream subjects test-sensor-logs --json | jq -r 'keys[]' | sort > subjects.out
# @TEST-EXEC: btest-diff subjects.out
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Paths with characters that are not valid in a subject token are percent-escaped into a single token.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef Log::default_writer=Log::WRITER_NATS;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(DNS::LOG);
	Log::disable_stream(HTTP::LOG);
	Log::disable_stream(SSL::LOG);

	for ( p in set("conn.new", "conn new", "conn*", "conn>", "conn%", "conn/x", "conn-0", "conn_red") )
		Log::add_filter(Conn::LOG, [$name=p, $path=p]);
	}

event zeek_done()
	{
	sleep(50msec);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer_backend_publish_errors", "*");
	for ( _, m in metrics )
		if ( m$value > 0 )
			print m$opts$name, m$label_values, m$value;
	}
