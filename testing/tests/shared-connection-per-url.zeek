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

# Wait up to 5 seconds for the log writer threads to process the
# expected number of publish acknowledgements.
function wait_for_acks(expected: double)
	{
	local i = 0;
	while ( i < 250 )
		{
		local acks = 0.0;
		for ( _, m in Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*") )
			if ( m$opts$name == "zeek_nats_log_writer_backend_publish_acks_total" )
				acks += m$value;

		if ( acks >= expected )
			return;

		sleep(20msec);
		++i;
		}
	}

event zeek_done()
	{
	# One ack per logged entry.
	wait_for_acks(9.0);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
