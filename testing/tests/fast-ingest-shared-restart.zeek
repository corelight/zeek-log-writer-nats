# @TEST-REQUIRES: have-nats
# @TEST-REQUIRES: have-fast-ingest
# @TEST-EXEC: private-nats-server start 4346
# @TEST-EXEC: zeek $FILES/fast-ingest-accounting.zeek %INPUT > out 2> stderr; nats -s nats://127.0.0.1:4346 stream subjects test-fast --json | tr -d ' \n' > subjects; private-nats-server stop 4346
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff subjects
#
# @TEST-DOC: Writers sharing a connection while the server restarts: writes while disconnected are dropped right away, buffered writes from before are published after the reconnect, and accounting balances for every writer.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::url = "nats://127.0.0.1:4346";
redef LogNATS::stream_name_template = "test-fast";
redef LogNATS::stream_subject_template = "test-fast.*";
redef LogNATS::publish_subject_template = "test-fast.{path}";
redef LogNATS::connection_sharing_policy = LogNATS::CONNECTION_SHARED;
redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;
redef LogNATS::dropped_writes_log = 0;

module Test;

export {
	redef enum Log::ID += { A, B, C };
}

function write_all(n: count)
	{
	FastIngestTest::write(A, "a", n);
	FastIngestTest::write(B, "b", n);
	FastIngestTest::write(C, "c", n);
	}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(A, [$columns=FastIngestTest::Info, $path="a"]);
	Log::create_stream(B, [$columns=FastIngestTest::Info, $path="b"]);
	Log::create_stream(C, [$columns=FastIngestTest::Info, $path="c"]);

	# Fewer than fast_ingest_writer_batch, these stay buffered in the
	# writers (no heartbeats run while zeek_init() sleeps).
	write_all(50);
	sleep(300msec);

	# system() runs in the background, leave time for the disconnect.
	system("private-nats-server stop 4346");
	sleep(1sec);
	write_all(10);
	sleep(300msec);

	system("private-nats-server start 4346");
	sleep(3sec);
	write_all(20);

	Log::flush(A);
	Log::flush(B);
	Log::flush(C);
	}

event zeek_done()
	{
	sleep(300msec);
	FastIngestTest::report();
	}
