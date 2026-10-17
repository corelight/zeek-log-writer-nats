# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT 2> zeek.stderr
# @TEST-EXEC: echo "== missing ==" >> out && nats subscribe 'test-sensor.logs.missing' --all -r --wait=$SUBSCRIBE_WAIT >> out
# @TEST-EXEC: echo "== notstring ==" >> out && nats subscribe 'test-sensor.logs.notstring' --all -r --wait=$SUBSCRIBE_WAIT >> out
# @TEST-EXEC: grep 'NATS: Raw body' zeek.stderr | sort > warnings
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff warnings
#
# @TEST-DOC: When the raw body field doesn't exist or isn't a string, a warning is reported at init and the JSON formatted record is published instead.

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef LogNATS::raw_body_fields += {
	["missing"] = "nope",
	["notstring"] = "id",
};

module Test;

export {
	redef enum Log::ID += { MISSING_LOG, NOTSTRING_LOG };

	type Info: record {
		id: count &log;
		body: string &log;
	};
}

event zeek_init()
	{
	Log::create_stream(MISSING_LOG, [$columns=Info, $path="missing"]);
	Log::create_stream(NOTSTRING_LOG, [$columns=Info, $path="notstring"]);

	Log::write(MISSING_LOG, [$id=1, $body="raw one"]);
	Log::write(NOTSTRING_LOG, [$id=2, $body="raw two"]);
	}
