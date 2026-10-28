# @TEST-REQUIRES: have-nats
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT
# @TEST-EXEC: for s in conn dns http ssl ; do echo ${s}; nats subscribe test-sensor.logs.${s} -r --all --wait=$SUBSCRIBE_WAIT ; done >> sensor-logs.jsonl
# @TEST-EXEC: btest-diff sensor-logs.jsonl
# @TEST-EXEC: for s in conn dns http ssl ; do nats stream info test-sensor-logs-${s} --json | grep -o '"allow_batched": *true' ; done > allow-batched
# @TEST-EXEC: btest-diff allow-batched
#
# @TEST-DOC: Fast-ingest publishing over a shared connection, streams are created with allow_batched.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef Log::default_writer=Log::WRITER_NATS;

redef LogNATS::stream_name_template = "test-sensor-logs-{path}";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_subject_template = "test-sensor.logs.{path}";

redef LogNATS::connection_sharing_policy = LogNATS::CONNECTION_SHARED;
redef LogNATS::publish_mode = LogNATS::PUBLISH_MODE_FAST_THREAD;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	}
