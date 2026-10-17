# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: echo "== raw (mapped) ==" >> out && nats subscribe 'test-sensor.logs.raw' --all -r --wait=$SUBSCRIBE_WAIT >> out
# @TEST-EXEC: echo "== other (unmapped) ==" >> out && nats subscribe 'test-sensor.logs.other' --all -r --wait=$SUBSCRIBE_WAIT | jq -c . >> out
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: A path listed in LogNATS::raw_body_fields publishes the bytes of the named string field as the message body instead of the JSON formatted record. Paths not listed are unchanged.

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef LogNATS::raw_body_fields += { ["raw"] = "body" };

module Test;

export {
	redef enum Log::ID += { RAW_LOG, OTHER_LOG };

	type Info: record {
		id: count &log;
		body: string &log;
	};
}

event zeek_init()
	{
	Log::create_stream(RAW_LOG, [$columns=Info, $path="raw"]);
	Log::create_stream(OTHER_LOG, [$columns=Info, $path="other"]);

	Log::write(RAW_LOG, [$id=1, $body="{\"a\":1,\"b\":\"x\"}"]);
	Log::write(RAW_LOG, [$id=2, $body="not json at all"]);
	Log::write(OTHER_LOG, [$id=3, $body="{\"a\":1}"]);
	}
