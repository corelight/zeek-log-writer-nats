# @TEST-REQUIRES: have-nats
# @TEST-REQUIRES: have-fast-ingest
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek $FILES/fast-ingest-accounting.zeek %INPUT > out 2> stderr
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: nats stream subjects test-sensor-logs --json | tr -d ' \n' > subjects
# @TEST-EXEC: btest-diff subjects
# @TEST-EXEC: ! grep -E 'PublishError|PublishTimeout|Dropped|not confirmed' stderr
#
# @TEST-DOC: Writers of a shared connection publishing to one stream share a fast-ingest batch. Acks are accounted exactly per writer, also while a writer finishes as others keep writing.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::connection_sharing_policy = LogNATS::CONNECTION_SHARED;
redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;
redef LogNATS::fast_ingest_flow = 50;
redef LogNATS::fast_ingest_max_outstanding_acks = 3;

module Test;

export {
	redef enum Log::ID += { A, B, C };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(A, [$columns=FastIngestTest::Info, $path="a"]);
	Log::create_stream(B, [$columns=FastIngestTest::Info, $path="b"]);
	Log::create_stream(C, [$columns=FastIngestTest::Info, $path="c"]);

	FastIngestTest::write(A, "a", 300);
	FastIngestTest::write(B, "b", 100);
	FastIngestTest::write(C, "c", 7);

	# B's writer finishes while the others keep writing.
	Log::remove_stream(B);
	sleep(200msec);

	FastIngestTest::write(A, "a", 200);
	FastIngestTest::write(C, "c", 3);

	# Commit, so the last partial flow window is acknowledged.
	Log::flush(A);
	Log::flush(C);
	}

event zeek_done()
	{
	sleep(200msec);
	FastIngestTest::report();
	}
