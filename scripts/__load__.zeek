module LogNATS;

export {
	type StreamStorage: enum {
		FILE,
		MEMORY,
	};

	type PathEscapePolicy: enum {
		# Substitute the path as is, e.g. to map "." onto subject hierarchy.
		ESCAPE_POLICY_NONE,
		# Escape as %hh, e.g. "conn.new" becomes "conn%2enew".
		ESCAPE_POLICY_PERCENT,
		# Escape as \xhh, e.g. "conn.new" becomes "conn\x2enew".
		ESCAPE_POLICY_HEX,
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

	# How the log path is escaped before it is substituted for {path} in
	# the templates above. With ESCAPE_POLICY_PERCENT or ESCAPE_POLICY_HEX,
	# bytes outside [A-Za-z0-9_-] are escaped, so the path is always one
	# subject token and a valid stream name, and paths such as "conn" or
	# "dhcp_fp" are unchanged. Defaults to ESCAPE_POLICY_NONE for backwards
	# compatibility.
	global path_escape_policy: PathEscapePolicy = ESCAPE_POLICY_NONE &redef;

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

	# Maximum outstanding asynchronous publishes that can be inflight at one time.
	global publish_async_max_pending: int = 0 &redef;
	# Amount of time to wait in a PublishAsync call when
	# there is MaxPending inflight messages, default is 200 ms.
	global publish_async_stall_wait: interval = 200msec &redef;
	# Amount of time to wait for async publish at shutdown.
	global publish_async_complete_max_wait: interval = 1000msec &redef;
}
