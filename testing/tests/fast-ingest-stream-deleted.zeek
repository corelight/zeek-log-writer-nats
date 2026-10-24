# @TEST-REQUIRES: have-nats
# @TEST-REQUIRES: have-fast-ingest
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek $FILES/fast-ingest-accounting.zeek %INPUT > out 2> stderr
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=$SUBSCRIBE_WAIT > sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
#
# @TEST-DOC: Writes fail while the stream is deleted, each in its own batch, and publishing recovers once the stream is recreated.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;
redef LogNATS::publish_error_log = 0;

# Queue every write right away, the test sleeps in zeek_init().
redef LogNATS::fast_ingest_writer_batch = 1;

module Test;

export {
	redef enum Log::ID += { LOG };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(LOG, [$columns=FastIngestTest::Info, $path="test"]);

	FastIngestTest::write(LOG, "test", 3);
	Log::flush(LOG);
	sleep(300msec);

	system("nats stream rm -f test-sensor-logs >/dev/null 2>&1");
	sleep(500msec);
	FastIngestTest::write(LOG, "test", 2);
	sleep(500msec);

	system("nats stream add --defaults --storage=file --allow-fast --subjects='test-sensor.logs.*' test-sensor-logs >/dev/null 2>&1");
	sleep(500msec);
	FastIngestTest::write(LOG, "test", 2);
	Log::flush(LOG);
	}

event zeek_done()
	{
	sleep(300msec);
	FastIngestTest::report();
	}
