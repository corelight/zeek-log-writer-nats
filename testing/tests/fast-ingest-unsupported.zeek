# @TEST-REQUIRES: ! have-fast-ingest
# @TEST-EXEC: zeek %INPUT 2> stderr
# @TEST-EXEC: grep -o 'NATS: PUBLISH_FAST_INGEST is not supported.*' stderr > errors
# @TEST-EXEC: btest-diff errors
#
# @TEST-DOC: Without orbit.c, PUBLISH_FAST_INGEST fails writer initialization.

redef LogNATS::publish_mode = LogNATS::PUBLISH_FAST_INGEST;
redef Log::default_writer=Log::WRITER_NATS;

module Test;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        data: string &log;
    };
}

event zeek_init()
	{
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(Reporter::LOG);
	Log::create_stream(Test::LOG, [$columns=Info, $path="test"]);
	Log::write(Test::LOG, [$data="msg-0"]);
	}
