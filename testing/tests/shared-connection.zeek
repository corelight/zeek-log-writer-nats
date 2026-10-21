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
	wait_for_acks(6.0);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
