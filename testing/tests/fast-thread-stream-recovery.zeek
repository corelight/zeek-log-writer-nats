# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT > out 2> stderr
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=$SUBSCRIBE_WAIT | sort >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: grep -c 'PublishError' stderr > errors
# @TEST-EXEC: btest-diff errors
#
# @TEST-DOC: Fast-ingest fails without stream and on a stream without allow_batched, but recovers once enabled.
#
# The error text races between orbit.c's error handler and jsFastPublish_Add() returning, so only count errors.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

redef LogNATS::create_stream = F;
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef LogNATS::publish_mode = LogNATS::PUBLISH_MODE_FAST_THREAD;
# Queue every write right away. The test sleeps in zeek_init(), where no
# writer heartbeats run to queue buffered writes.
redef LogNATS::fast_publish_thread_writer_batch = 1;
redef LogNATS::publish_error_log = 1;

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

	sleep(100msec);
	system("nats stream edit -f --allow-fast test-sensor-logs >/dev/null 2>&1");
	sleep(500msec);

	Log::write(Test::LOG, [$ts=double_to_time(2.0), $data="msg-2"]);
	}

event zeek_done()
	{
	sleep(50msec);

	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
