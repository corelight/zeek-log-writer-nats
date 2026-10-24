# @TEST-REQUIRES: have-nats
# @TEST-REQUIRES: have-fast-ingest
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek $FILES/fast-ingest-accounting.zeek %INPUT > out 2> stderr
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: grep -c "fast_ingest_flow 1000 exceeds the server's maximum, using 500" stderr > warnings
# @TEST-EXEC: btest-diff warnings
#
# @TEST-DOC: A fast_ingest_flow above the server's maximum of 500 is clamped, with a single warning for all writers.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::connection_sharing_policy = LogNATS::CONNECTION_SHARED;
redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;
redef LogNATS::fast_ingest_flow = 1000;

module Test;

export {
	redef enum Log::ID += { A, B };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(A, [$columns=FastIngestTest::Info, $path="a"]);
	Log::create_stream(B, [$columns=FastIngestTest::Info, $path="b"]);

	FastIngestTest::write(A, "a", 10);
	FastIngestTest::write(B, "b", 10);
	Log::flush(A);
	Log::flush(B);
	}

event zeek_done()
	{
	sleep(200msec);
	FastIngestTest::report();
	}
