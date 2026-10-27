# @TEST-REQUIRES: have-nats
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap %INPUT 2>stderr
# @TEST-EXEC: grep -q "NATS: Connection::Create.* failed:.*invalid port" stderr
#
# @TEST-DOC: What happens when there's an invalid URL?

redef Log::default_writer = Log::WRITER_NATS;

redef LogNATS::url = "http://127.0.0.1:-1/broken";

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(DNS::LOG);
	Log::disable_stream(HTTP::LOG);
	Log::disable_stream(SSL::LOG);
	}
