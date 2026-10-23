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

	type ConnectionSharingPolicy: enum {
		# Every writer uses a dedicated connection to the NATS server.
		CONNECTION_EXCLUSIVE,
		# Log writers with the same URL share a single connection
		# to the NATS server, but use individual JetStream contexts.
		CONNECTION_SHARED,
	};

	type PublishMode: enum {
		# Asynchronous publishing with one acknowledgement per message
		# (js_PublishMsgAsync). See the publish_async_* options.
		PUBLISH_ASYNC,
		# Fast-ingest batch publishing (NATS ADR-50) with server driven
		# flow control and one acknowledgement every fast_ingest_flow
		# messages. Requires nats-server 2.14 or later and the plugin
		# built with orbit.c's jetstream-extra library. See the
		# fast_ingest_* options.
		PUBLISH_FAST_INGEST,
	};

	global url: string = "nats://localhost:4222" &redef;

	# Default connection_sharing_policy.
	#
	# By default, every Zeek log writer receives a dedicated connection
	# to the NATS server configured via url. Setting connection_sharing_policy
	# to CONNECTION_SHARED instead makes all log writers using the same
	# url value to share a single connection to the NATS server.
	#
	# The policy may be set on a per log writer via the connection_sharing_policy
	# entry in the writer's config table.
	global connection_sharing_policy = CONNECTION_EXCLUSIVE &redef;

	# The connection timeout configured via libnats.
	global connection_timeout = 1000msec &redef;

	# The ping interval configured via libnats.
	global ping_interval = 5000msec &redef;

	# The reconnect wait configured via libnats.
	global reconnect_wait = 100msec &redef;

	# The jitter configured via libnats.
	global jitter = 200msec &redef;

	# The jitter for tls configured via libnats.
	global jitter_tls = 200msec &redef;

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

	# Log every n'th asynchronous publish error, or none if set to 0.
	# By default, log the first and then every thousandths.
	global publish_error_log = 1000 &redef;

	# Log every n'th dropped write error, or none if set to 0.
	# By default, log the first and then every thousandths.
	global dropped_writes_log = 1000 &redef;

	# Maximum outstanding asynchronous publishes that can be inflight at one time.
	global publish_async_max_pending: int = 100000 &redef;

	# How long to wait for the server to send an ACK before considering
	# a js_PublishAsyncMsg() timed out. Timeouts are tracked in the
	# zeek_nats_log_writer_backend_publish_timeouts_total metric and
	# also included in zeek_nats_log_writer_backend_publish_errors_total.
	global publish_async_max_wait: interval = 10000msec &redef;

	# Amount of time to wait in a PublishMsgAsync call when
	# there is MaxPending inflight messages, default is 1ms.
	global publish_async_stall_wait: interval = 1msec &redef;

	# If T, will discard js_PublishMsgAsync if the log writers
	# own pending tracking indicates publish_async_max_pending
	# has been exceeded. libnats does not provide a non-stalling
	# mode, but generally we never want DoWrite() to block, so
	# this defaults to T.
	global publish_async_no_stall = T &redef;

	# Amount of time to wait for async publish at shutdown.
	global publish_async_complete_max_wait: interval = 1000msec &redef;

	# How log writers publish to JetStream.
	#
	# The mode may be set on a per log writer via the publish_mode
	# entry in the writer's config table.
	global publish_mode: PublishMode = PUBLISH_ASYNC &redef;

	# With PUBLISH_FAST_INGEST, the requested number of messages per
	# flow acknowledgement. The server starts lower and may adjust
	# the value at runtime, but never above this one (1-65535).
	global fast_ingest_flow: count = 100 &redef;

	# With PUBLISH_FAST_INGEST, the number of flow acknowledgements that
	# may be outstanding before a write blocks waiting for the server (1-3).
	global fast_ingest_max_outstanding_acks: count = 2 &redef;

	# With PUBLISH_FAST_INGEST, the maximum time a write blocks waiting
	# for a flow acknowledgement. Hitting it ends the batch, the next
	# write starts a new one. Unlike PUBLISH_ASYNC with
	# publish_async_no_stall, fast-ingest writes block rather than drop
	# when the server applies backpressure.
	global fast_ingest_ack_timeout: interval = 1000msec &redef;

	# With PUBLISH_FAST_INGEST, continue a batch when the server detects
	# lost messages. Lost messages are counted as publish errors. If F,
	# a gap ends the batch and the next write starts a new one.
	global fast_ingest_continue_on_gap: bool = T &redef;

	# With PUBLISH_FAST_INGEST, a log flush (e.g. Log::flush()) also commits
	# the current batch.
	#
	# With PUBLISH_FAST_INGEST, commit a batch on the next write when no
	# message has been published for this long. The server abandons
	# batches after 10 seconds without traffic, so keep this below that.
	# Set to 0sec to disable.
	global fast_ingest_idle_timeout: interval = 5sec &redef;

	# With PUBLISH_FAST_INGEST, log writers of a connection publishing to
	# the same stream share one batch. Each writer buffers this many
	# writes and publishes them to the batch at once, which keeps writers
	# from contending on it per write. Buffered writes are also published
	# on flush and with every writer heartbeat (Threading::heartbeat_interval).
	global fast_ingest_writer_batch: count = 64 &redef;
}
