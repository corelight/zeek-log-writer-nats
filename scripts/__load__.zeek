module LogNATS;

export {
	type StreamStorage: enum {
		FILE,
		MEMORY,
	};

	global url: string = "nats://localhost:4222" &redef;

	# This template is interpolated to produce the subject to publish to.
	global publish_subject_template: string = "sensor.logs.{path}" &redef;

	# This template is used to create the stream name.
	global stream_name_template: string = "sensor-logs-{path}" &redef;

	# This template is used to create subject of the stream.
	# Use a wildcard match .* without the {path} variable if only a
	# single stream is used.
	global stream_subject_template: string = "sensor.logs.{path}" &redef;
	global stream_storage: StreamStorage = FILE &redef;

	global include_unset_fields: bool = F &redef;

	# Format of the timestamp fields (e.g. ts, _write_ts) in the JSON output.
	# Accepts the same values as LogAscii::json_timestamps: JSON::TS_EPOCH,
	# JSON::TS_MILLIS, JSON::TS_MILLIS_UNSIGNED, JSON::TS_ISO8601.
	global json_timestamps: JSON::TimestampFormat = JSON::TS_EPOCH &redef;

	# By default, zeek-log-writer-nats will automatically create a JetStream
	# stream to publish on. If create_stream is false, then the stream must be
	# created and configured manually to work with zeek-log-writer-nats.
	global create_stream: bool = T &redef;

	# Log every n'th asynchronous publish error, or
	# none if set to 0. By default, log each of them.
	global publish_error_log = 1 &redef;

	# Log every n'th dropped write error, or
	# none if set to 0. By default, log each of them.
	global dropped_writes_log = 1 &redef;

	# If true, all log streams of a Zeek process publishing to the same url
	# share a single NATS connection. If false, each log stream uses its own.
	global share_connection: bool = T &redef;

	# Maximum outstanding asynchronous publishes that can be inflight at one time.
	# With share_connection, this limit applies to all log streams publishing
	# to the same url combined, otherwise to each of them separately.
	# A value of 0 means unlimited.
	global publish_async_max_pending: int = 256 &redef;
	# Amount of time to wait in a PublishAsync call when
	# there is MaxPending inflight messages, default is 200 ms.
	# If the wait times out, the write is dropped and counted
	# in dropped_writes.
	global publish_async_stall_wait: interval = 200msec &redef;
	# Amount of time to wait for async publish at shutdown.
	global publish_async_complete_max_wait: interval = 1000msec &redef;
}
