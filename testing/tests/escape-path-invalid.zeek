# @TEST-REQUIRES: have-nats
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT 2> stderr
# @TEST-EXEC: grep -q "NATS: Invalid path_escape_policy LogNATS::ESCAPE_POLICY_BOGUS" stderr
#
# @TEST-DOC: An unknown per-filter path_escape_policy is reported as an error.

redef Log::default_writer=Log::WRITER_NATS;

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(DNS::LOG);
	Log::disable_stream(HTTP::LOG);
	Log::disable_stream(SSL::LOG);

	Log::add_filter(Conn::LOG, [$name="bogus", $path="conn_bogus",
	                            $config=table(["path_escape_policy"] = "LogNATS::ESCAPE_POLICY_BOGUS")]);
	}
