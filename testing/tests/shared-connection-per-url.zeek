# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT | sort > out
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Writers with a different url use a separate NATS connection and acks are attributed to the right writer.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::stream_name_template = "test-sensor-logs-{path}";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_subject_template = "test-sensor.logs.{path}";

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);

	# Same server, but a different url, so a separate connection.
	Log::add_filter(Conn::LOG, [
		$name="other-url",
		$path="conn-other",
		$config=table(["url"] = "nats://127.0.0.1:4222"),
	]);
	}

event zeek_done()
	{
	sleep(50msec);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
