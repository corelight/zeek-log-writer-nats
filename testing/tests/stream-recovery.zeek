# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT > out
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=$SUBSCRIBE_WAIT | sort >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Publishing fails without stream, but recovers later with stream.

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

# Important for this testing scenario. write_buffer_size must be 1 so
# Log::write calls don't get buffered.
redef Log::write_buffer_size = 1;
redef Log::default_writer=Log::WRITER_NATS;

module Test;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:   time &log;
        data: string &log;
    };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(Test::LOG, [$columns=Info, $path="test"]);

	Log::write(Test::LOG, [$ts=double_to_time(0.0), $data="msg-0"]);

	sleep(100msec);
	system("nats stream add --defaults --storage=file --subjects='test-sensor.logs.*' test-sensor-logs >/dev/null 2>&1");
	sleep(500msec);

	Log::write(Test::LOG, [$ts=double_to_time(1.0), $data="msg-1"]);
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
	# One publish error for msg-0, one ack for msg-1.
	wait_for_responses(2.0);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
