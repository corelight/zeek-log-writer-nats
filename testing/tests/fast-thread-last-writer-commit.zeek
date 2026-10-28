# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek $FILES/fast-thread-accounting.zeek %INPUT 2> stderr
# @TEST-EXEC: nats stream info test-sensor-logs --json | grep -o '"messages": *[0-9]*' > messages
# @TEST-EXEC: btest-diff messages
# @TEST-EXEC: ! grep -E 'PublishError|PublishTimeout|Dropped|not confirmed' stderr
#
# @TEST-DOC: Without a flush, writes buffered and in flight at shutdown are published, and the last writer finishing commits the shared batch.

redef Log::default_writer = Log::WRITER_NATS;
redef Log::write_buffer_size = 1;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::connection_sharing_policy = LogNATS::CONNECTION_SHARED;
redef LogNATS::publish_mode = LogNATS::PUBLISH_MODE_FAST_THREAD;

module Test;

export {
	redef enum Log::ID += { A, B };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::create_stream(A, [$columns=FastIngestTest::Info, $path="a"]);
	Log::create_stream(B, [$columns=FastIngestTest::Info, $path="b"]);

	# Neither a multiple of fast_publish_thread_writer_batch nor of the flow.
	FastIngestTest::write(A, "a", 333);
	FastIngestTest::write(B, "b", 77);
	}
