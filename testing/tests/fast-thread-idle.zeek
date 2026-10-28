# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT > out
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=$SUBSCRIBE_WAIT | sort >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: An idle fast-ingest batch is committed and the next write starts a new batch.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef LogNATS::publish_mode = LogNATS::PUBLISH_MODE_FAST_THREAD;
# Queue every write right away. The test sleeps in zeek_init(), where no
# writer heartbeats run to queue buffered writes.
redef LogNATS::fast_publish_thread_writer_batch = 1;
redef LogNATS::fast_publish_idle_timeout = 100msec;

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
	sleep(300msec);
	Log::write(Test::LOG, [$ts=double_to_time(1.0), $data="msg-1"]);
	}

event zeek_done()
	{
	sleep(50msec);

	# The commit of the first batch acknowledged msg-0, msg-1 is
	# pending in the second batch.
	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*");
	for ( _, m in metrics )
		print m$opts$name, m$label_values, m$value;
	}
