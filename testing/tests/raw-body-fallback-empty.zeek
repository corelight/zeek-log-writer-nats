# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT 2> zeek.stderr
# @TEST-EXEC: nats subscribe 'test-sensor.logs.raw' --all -r --wait=$SUBSCRIBE_WAIT >> out
# @TEST-EXEC: grep 'NATS: Raw body' zeek.stderr > warnings
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff warnings
#
# @TEST-DOC: When the raw body field of a record is empty or unset, the JSON formatted record is published instead, and a warning is reported once per writer.

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef LogNATS::raw_body_fields += { ["raw"] = "body" };

module Test;

export {
	redef enum Log::ID += { RAW_LOG };

	type Info: record {
		id: count &log;
		body: string &log &optional;
	};
}

event zeek_init()
	{
	Log::create_stream(RAW_LOG, [$columns=Info, $path="raw"]);

	Log::write(RAW_LOG, [$id=1, $body="raw one"]);
	Log::write(RAW_LOG, [$id=2, $body=""]);
	Log::write(RAW_LOG, [$id=3]);
	Log::write(RAW_LOG, [$id=4, $body=""]);
	Log::write(RAW_LOG, [$id=5, $body="raw five"]);
	}
