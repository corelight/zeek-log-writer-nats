# @TEST-REQUIRES: have-nats
# @TEST-REQUIRES: have-fast-ingest
# @TEST-EXEC: private-nats-server start 4345
# @TEST-EXEC: zeek $FILES/fast-ingest-accounting.zeek %INPUT > out 2> stderr; nats -s nats://127.0.0.1:4345 subscribe test-fast.test --all -r --wait=$SUBSCRIBE_WAIT | tail -1 > last; nats -s nats://127.0.0.1:4345 stream info test-fast --json | grep -o '"messages": *[0-9]*' > messages; private-nats-server stop 4345
# @TEST-EXEC: grep -o 'accounted=.' out > accounted
# @TEST-EXEC: btest-diff accounted
# @TEST-EXEC: btest-diff last
# @TEST-EXEC: btest-diff messages
#
# @TEST-DOC: A server restart in the middle of a batch neither hangs nor crashes. The batch the server lost is ended after the reconnect, every write ends up acked, failed, timed out or dropped, and writes after the restart are delivered.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::url = "nats://127.0.0.1:4345";
redef LogNATS::stream_name_template = "test-fast";
redef LogNATS::stream_subject_template = "test-fast.*";
redef LogNATS::publish_subject_template = "test-fast.{path}";
redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;
redef LogNATS::publish_error_log = 0;
redef LogNATS::dropped_writes_log = 0;

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

	# The batch is still open when the server restarts.
	FastIngestTest::write(LOG, "test", 20);
	sleep(300msec);
	# system() runs in the background, leave time to restart and reconnect.
	system("private-nats-server restart 4345");
	sleep(3sec);

	FastIngestTest::write(LOG, "test", 20);
	Log::flush(LOG);
	}

event zeek_done()
	{
	sleep(300msec);
	FastIngestTest::report();
	}
