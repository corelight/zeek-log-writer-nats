# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT > out
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=$SUBSCRIBE_WAIT | sort >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Removing one NATS log stream mid-run keeps the shared connection and the other writer publishing.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

# Write each entry immediately rather than buffering.
redef Log::write_buffer_size = 1;

# Run on wall clock time without input until terminate() is called.
redef exit_only_after_terminate = T;

module Test;

export {
	redef enum Log::ID += { A, B };

	type Info: record {
		ts:   time &log;
		data: string &log;
	};
}

function nats_only(id: Log::ID)
	{
	Log::remove_default_filter(id);
	Log::add_filter(id, [$name="nats", $writer=Log::WRITER_NATS]);
	}

function write_msgs(id: Log::ID, prefix: string, from: count, to: count)
	{
	local i = from;
	while ( i < to )
		{
		Log::write(id, [$ts=double_to_time(i), $data=fmt("%s-%d", prefix, i)]);
		++i;
		}
	}

function print_metrics(label: string)
	{
	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer*", "*");
	local lines: vector of string;
	for ( _, m in metrics )
		lines += fmt("%s %s %s %s", label, m$opts$name, m$label_values, m$value);

	sort(lines, strcmp);
	for ( _, l in lines )
		print l;
	}

event finish()
	{
	terminate();
	}

event after_removal()
	{
	print_metrics("after-removal");

	# Only B keeps publishing.
	write_msgs(B, "b", 5, 10);

	schedule 500msec { finish() };
	}

event remove_a()
	{
	print_metrics("before-removal");
	Log::remove_stream(A);
	schedule 500msec { after_removal() };
	}

event zeek_init()
	{
	Log::create_stream(A, [$columns=Info, $path="test-a"]);
	Log::create_stream(B, [$columns=Info, $path="test-b"]);
	nats_only(A);
	nats_only(B);

	write_msgs(A, "a", 0, 5);
	write_msgs(B, "b", 0, 5);

	schedule 500msec { remove_a() };
	}

event zeek_done()
	{
	# Give the log writer threads a bit of time to process all the acks
	# and update the metrics.
	sleep(50msec);
	print_metrics("done");
	}
