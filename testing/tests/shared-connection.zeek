# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT | sort > out
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: All writers publishing to the same url share a single NATS connection.

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
	}

event zeek_done()
	{
	sleep(50msec);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
