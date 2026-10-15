# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT > out
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=50ms | sort >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Publishing should not work if no stream is created.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef LogNATS::create_stream = F;
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef Log::default_writer=Log::WRITER_NATS;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	}

# Wait up to 5 seconds for the log writer threads to process the
# expected number of publish acknowledgements and errors.
function wait_for_responses(expected: double)
	{
	local i = 0;
	while ( i < 250 )
		{
		local responses = 0.0;
		for ( _, m in Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*") )
			if ( m$opts$name == "zeek_nats_log_writer_backend_publish_acks_total" ||
			     m$opts$name == "zeek_nats_log_writer_backend_publish_errors_total" )
				responses += m$value;

		if ( responses >= expected )
			return;

		sleep(20msec);
		++i;
		}
	}

event zeek_done()
	{
	# One publish error per logged entry.
	wait_for_responses(6.0);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
