# @TEST-EXEC: zeek -NN Zeek::Log_Writer_NATS | sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output

@if ( Version::number >= 70100 )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif
