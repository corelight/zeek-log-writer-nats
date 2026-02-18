# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT
# @TEST-EXEC: nats subscribe 'test-sensor.logs.*' --all -r --wait=10ms | sort >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
#
# @TEST-DOC: Configure just a single stream with sensor.logs.* subject.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef NATS::publish_subject_template = "test-sensor.logs.{path}";
redef NATS::stream_name_template = "test-sensor-logs";
redef NATS::stream_subject_template = "test-sensor.logs.*";

redef Log::default_writer=Log::WRITER_NATS;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	}
