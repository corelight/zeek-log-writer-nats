# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT
# @TEST-EXEC: nats stream subjects test-sensor-logs --json | jq -r 'keys[]' | sort > subjects.out
# @TEST-EXEC: btest-diff subjects.out
#
# @TEST-DOC: The global path_escape_policy applies unless a filter overrides it via path_escape_policy in its config.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.>";
redef LogNATS::path_escape_policy = LogNATS::ESCAPE_POLICY_HEX;

redef Log::default_writer=Log::WRITER_NATS;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(DNS::LOG);
	Log::disable_stream(HTTP::LOG);
	Log::disable_stream(SSL::LOG);

	Log::add_filter(Conn::LOG, [$name="hex", $path="conn.hex"]);
	Log::add_filter(Conn::LOG, [$name="percent", $path="conn.percent",
	                            $config=table(["path_escape_policy"] = "LogNATS::ESCAPE_POLICY_PERCENT")]);
	Log::add_filter(Conn::LOG, [$name="none", $path="conn.none",
	                            $config=table(["path_escape_policy"] = "LogNATS::ESCAPE_POLICY_NONE")]);
	}
