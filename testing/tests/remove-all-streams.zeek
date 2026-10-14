# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT > out
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=$SUBSCRIBE_WAIT | sort >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Removing all NATS writers mid-run closes the shared connection; a new writer establishes a new one.

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
	redef enum Log::ID += { A, B, C };

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

event after_recreate()
	{
	print_metrics("after-recreate");
	schedule 100msec { finish() };
	}

event recreate()
	{
	print_metrics("after-removal");

	# All NATS writers and thereby the shared client are gone. A new
	# stream's writer has to establish a new connection.
	Log::create_stream(C, [$columns=Info, $path="test-c"]);
	nats_only(C);

	write_msgs(C, "c", 0, 5);

	schedule 500msec { after_recreate() };
	}

event remove_all()
	{
	print_metrics("before-removal");
	Log::remove_stream(A);
	Log::remove_stream(B);
	schedule 500msec { recreate() };
	}

event zeek_init()
	{
	Log::create_stream(A, [$columns=Info, $path="test-a"]);
	Log::create_stream(B, [$columns=Info, $path="test-b"]);
	nats_only(A);
	nats_only(B);

	write_msgs(A, "a", 0, 5);
	write_msgs(B, "b", 0, 5);

	schedule 500msec { remove_all() };
	}

event zeek_done()
	{
	sleep(50msec);
	print_metrics("done");
	}
