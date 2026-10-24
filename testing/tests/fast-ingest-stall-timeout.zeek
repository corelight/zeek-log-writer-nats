# @TEST-REQUIRES: have-nats
# @TEST-REQUIRES: have-fast-ingest
# @TEST-EXEC: private-nats-server start 4342
# @TEST-EXEC: zeek $FILES/fast-ingest-accounting.zeek %INPUT > out 2> stderr; nats -s nats://127.0.0.1:4342 stream info test-fast --json | grep -o '"messages": *[0-9]*' > messages; private-nats-server stop 4342
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff messages
# @TEST-EXEC: grep -c PublishTimeout stderr > timeouts-logged
# @TEST-EXEC: btest-diff timeouts-logged
# @TEST-EXEC: ! grep -E 'PublishError|Dropped' stderr
#
# @TEST-DOC: When neither the flow ack nor the commit arrives within the ack timeout, the message in flight is counted as a publish timeout, not an error. The server still stores it once it's back.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::url = "nats://127.0.0.1:4342";
redef LogNATS::stream_name_template = "test-fast";
redef LogNATS::stream_subject_template = "test-fast.*";
redef LogNATS::publish_subject_template = "test-fast.{path}";
redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;

# Queue every write right away, the test sleeps in zeek_init(). A flow
# window of a single message makes the second write wait for its ack.
redef LogNATS::fast_ingest_writer_batch = 1;
redef LogNATS::fast_ingest_flow = 1;
redef LogNATS::fast_ingest_max_outstanding_acks = 1;
redef LogNATS::fast_ingest_ack_timeout = 1sec;

module Test;

export {
	redef enum Log::ID += { LOG };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(LOG, [$columns=FastIngestTest::Info, $path="test"]);

	FastIngestTest::write(LOG, "test", 1);
	sleep(300msec);

	# Paused past both the ack timeout of the second write and the
	# commit's timeout after it.
	system("kill -STOP $(cat nats-4342.pid)");
	# system() runs in the background, let the pause take effect.
	sleep(100msec);
	FastIngestTest::write(LOG, "test", 1);
	sleep(2600msec);
	system("kill -CONT $(cat nats-4342.pid)");
	sleep(300msec);

	FastIngestTest::write(LOG, "test", 1);
	Log::flush(LOG);
	}

event zeek_done()
	{
	sleep(300msec);
	FastIngestTest::report();
	}
