# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT > out
# @TEST-EXEC: nats stream subjects test-sensor-logs --json | jq -r 'keys[]' | sort > subjects.out
# @TEST-EXEC: btest-diff subjects.out
#
# @TEST-DOC: With escape_path disabled for a filter, its raw path is substituted, so "." maps onto subject hierarchy.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_name_template = "test-sensor-logs";
redef LogNATS::stream_subject_template = "test-sensor.logs.>";

redef Log::default_writer=Log::WRITER_NATS;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(DNS::LOG);
	Log::disable_stream(HTTP::LOG);
	Log::disable_stream(SSL::LOG);

	Log::add_filter(Conn::LOG, [$name="escaped", $path="conn.escaped"]);
	Log::add_filter(Conn::LOG, [$name="raw", $path="conn.raw", $config=table(["escape_path"] = "F")]);
	}
