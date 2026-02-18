# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT
# @TEST-EXEC: for s in conn dns http ssl ; do echo ${s}; nats subscribe test-sensor.logs.${s} -r --all --wait=10ms ; done >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef Log::default_writer=Log::WRITER_NATS;

redef NATS::stream_name_template = "test-sensor-logs-{path}";
redef NATS::publish_subject_template = "test-sensor.logs.{path}";
redef NATS::stream_subject_template = "test-sensor.logs.{path}";
redef NATS::stream_subject_template = "test-sensor.logs.{path}";

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	}
