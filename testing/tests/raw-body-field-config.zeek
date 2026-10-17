# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: echo "== enabled (per-filter raw_body_field) ==" >> out && nats subscribe 'test-sensor.logs.enabled' --all -r --wait=$SUBSCRIBE_WAIT >> out
# @TEST-EXEC: echo "== disabled (per-filter empty raw_body_field) ==" >> out && nats subscribe 'test-sensor.logs.disabled' --all -r --wait=$SUBSCRIBE_WAIT | jq -c . >> out
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: A per-filter $config["raw_body_field"] overrides LogNATS::raw_body_fields for that filter's path. A field name enables raw bodies for a path that isn't in the table, and an empty value disables them for a path that is.

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_subject_template = "test-sensor.logs.*";

redef LogNATS::raw_body_fields += { ["disabled"] = "body" };

module Test;

export {
	redef enum Log::ID += { ENABLED_LOG, DISABLED_LOG };

	type Info: record {
		id: count &log;
		body: string &log;
	};
}

event zeek_init()
	{
	Log::create_stream(ENABLED_LOG, [$columns=Info, $path="enabled"]);
	Log::create_stream(DISABLED_LOG, [$columns=Info, $path="disabled"]);

	local f = Log::get_filter(ENABLED_LOG, "default");
	f$config = table(["raw_body_field"] = "body");
	Log::remove_filter(ENABLED_LOG, "default");
	Log::add_filter(ENABLED_LOG, f);

	f = Log::get_filter(DISABLED_LOG, "default");
	f$config = table(["raw_body_field"] = "");
	Log::remove_filter(DISABLED_LOG, "default");
	Log::add_filter(DISABLED_LOG, f);

	Log::write(ENABLED_LOG, [$id=1, $body="raw one"]);
	Log::write(DISABLED_LOG, [$id=2, $body="raw two"]);
	}
