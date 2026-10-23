# @TEST-REQUIRES: have-nats
# @TEST-REQUIRES: have-fast-ingest
# @TEST-EXEC: nats-cleanup
# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT | sort > out
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Every fast-ingest write is accounted as acknowledged or pending, with a small flow so acks arrive mid-batch.

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

@if ( Version::number >= 80100 )
@load policy/protocols/dns/disable-opcode-log-fields
@endif

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::stream_name_template = "test-sensor-logs-{path}";
redef LogNATS::publish_subject_template = "test-sensor.logs.{path}";
redef LogNATS::stream_subject_template = "test-sensor.logs.{path}";

redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;
redef LogNATS::fast_ingest_flow = 2;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	}

event Pcap::file_done(path: string)
	{
@if ( Version::number >= 80100 )
	Log::flush_all();
@else
	Log::flush(Conn::LOG);
	Log::flush(HTTP::LOG);
	Log::flush(DNS::LOG);
@endif
	}

event zeek_done()
	{
	sleep(50msec);

	# Acks arriving after the last write are only accounted with the next
	# write or the final commit, so report acks and pending together.
	local accounted: table[string] of double;
	local path: string;
	local metrics = Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*");
	for ( _, m in metrics )
		{
		path = m$label_values[1];
		if ( m$opts$name == "zeek_nats_log_writer_backend_publish_acks_total" ||
		     m$opts$name == "zeek_nats_log_writer_backend_publishes_pending" )
			{
			if ( path !in accounted )
				accounted[path] = 0.0;
			accounted[path] += m$value;
			}
		else
			print m$opts$name, m$label_values, m$value;
		}

	for ( path, v in accounted )
		print "accounted", path, v;
	}
