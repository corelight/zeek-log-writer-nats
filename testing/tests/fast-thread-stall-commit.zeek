# @TEST-REQUIRES: have-nats
# @TEST-EXEC: private-nats-server start 4341
# @TEST-EXEC: zeek $FILES/fast-thread-accounting.zeek %INPUT > out 2> stderr; nats -s nats://127.0.0.1:4341 stream info test-fast --json | grep -o '"messages": *[0-9]*' > messages; private-nats-server stop 4341
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff messages
# @TEST-EXEC: ! grep -E 'PublishError|PublishTimeout|Dropped' stderr
#
# @TEST-DOC: A server pause longer than the ack timeout ends the batch, but committing it once the server is back confirms the message in flight instead of counting it as a timeout.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::url = "nats://127.0.0.1:4341";
redef LogNATS::stream_name_template = "test-fast";
redef LogNATS::stream_subject_template = "test-fast.*";
redef LogNATS::publish_subject_template = "test-fast.{path}";
redef LogNATS::publish_mode = LogNATS::PUBLISH_MODE_FAST_THREAD;

# Queue every write right away, the test sleeps in zeek_init(). A flow
# window of a single message makes the second write wait for its ack.
redef LogNATS::fast_publish_thread_writer_batch = 1;
redef LogNATS::fast_publish_flow = 1;
redef LogNATS::fast_publish_max_outstanding_acks = 1;
redef LogNATS::fast_publish_commit_timeout = 1sec;

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

	# The second write times out after one second, the commit of the ended
	# batch then waits up to another second, during which the server is back.
	system("kill -STOP $(cat nats-4341.pid)");
	# system() runs in the background, let the pause take effect.
	sleep(100msec);
	FastIngestTest::write(LOG, "test", 1);
	sleep(1500msec);
	system("kill -CONT $(cat nats-4341.pid)");
	sleep(300msec);

	FastIngestTest::write(LOG, "test", 1);
	Log::flush(LOG);
	}

event zeek_done()
	{
	sleep(300msec);
	FastIngestTest::report();
	}
