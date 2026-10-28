# @TEST-REQUIRES: have-nats
# @TEST-EXEC: private-nats-server start 4343
# @TEST-EXEC: zeek $FILES/fast-thread-accounting.zeek %INPUT > out 2> stderr; nats -s nats://127.0.0.1:4343 stream info test-fast --json | grep -o '"messages": *[0-9]*' > messages; private-nats-server stop 4343
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff messages
# @TEST-EXEC: grep -c 'fast-ingest queue full' stderr > drops-logged
# @TEST-EXEC: btest-diff drops-logged
#
# @TEST-DOC: With publish_async_no_stall, writes are dropped and counted once the shared batch's queue stays full for fast_publish_thread_stall_wait, rather than blocking the log writer.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::url = "nats://127.0.0.1:4343";
redef LogNATS::stream_name_template = "test-fast";
redef LogNATS::stream_subject_template = "test-fast.*";
redef LogNATS::publish_subject_template = "test-fast.{path}";
redef LogNATS::publish_mode = LogNATS::PUBLISH_MODE_FAST_THREAD;

# Queue every write right away, the test sleeps in zeek_init(). The queue
# only takes a write when it's empty, and a flow window of a single message
# makes publishing wait for each message's ack.
redef LogNATS::fast_publish_thread_writer_batch = 1;
redef LogNATS::fast_publish_flow = 1;
redef LogNATS::fast_publish_max_outstanding_acks = 1;
redef LogNATS::fast_publish_thread_queue_size = 1;
redef LogNATS::fast_publish_thread_stall_wait = 10msec;

module Test;

export {
	redef enum Log::ID += { LOG };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(LOG, [$columns=FastIngestTest::Info, $path="test"]);

	# Creates the stream and starts the batch.
	FastIngestTest::write(LOG, "test", 1);
	sleep(300msec);

	# While the server is paused, the publisher thread waits for the flow
	# ack of the second write. The third write fills the queue, the
	# remaining eight are dropped.
	system("kill -STOP $(cat nats-4343.pid)");
	# system() runs in the background, let the pause take effect.
	sleep(100msec);
	FastIngestTest::write(LOG, "test", 1);
	sleep(300msec);
	FastIngestTest::write(LOG, "test", 9);
	sleep(300msec);
	system("kill -CONT $(cat nats-4343.pid)");

	Log::flush(LOG);
	}

event zeek_done()
	{
	sleep(300msec);
	FastIngestTest::report();
	}
