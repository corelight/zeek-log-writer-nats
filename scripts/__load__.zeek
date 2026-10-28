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
		# High-throughput fire-and-forget mode until the connection's
		# buffer is full without acks.
		PUBLISH_MODE_CORE,
		# js_PublishAsyncMsg() style including ack processing. Heavy.
		PUBLISH_MODE_ASYNC,
		# Fast-ingest batch publish.
		# https://docs.nats.io/learn/jetstream/advanced-publishing#fast-ingest-batch-publish
		PUBLISH_MODE_FAST,
		# Fast-ingest batch publish from a publisher thread, with one
		# batch shared by all log writers of a connection that publish
		# to the same stream.
		PUBLISH_MODE_FAST_THREAD,
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

	# Globally selected publish_mode for all log writers.
	global publish_mode = PUBLISH_MODE_ASYNC &redef;

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

	# If T, streams created by the log writer use persist_mode async: the
	# server acknowledges messages before they are flushed to storage.
	# Requires nats-server 2.12 or later.
	global stream_persist_async: bool = F &redef;

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
	#
	# With PUBLISH_MODE_FAST_THREAD, drop writes rather than block when
	# the queue of the shared batch is full, see
	# fast_publish_thread_stall_wait. If F, writers wait for space
	# without limit: the server's backpressure then propagates into
	# Zeek's log writer queues, which grow without bound under
	# sustained overload.
	global publish_async_no_stall = T &redef;

	# Amount of time to wait for async publish at shutdown.
	global publish_async_complete_max_wait: interval = 1000msec &redef;

	type FastPublishBatchPolicy: enum {
		# Each logging thread receives its own batch.
		BATCH_EXCLUSIVE,
		# A single batch is shared across all logging threads.
		BATCH_SHARED,

		# Some ideas
		# BATCH_SUBJECT,
		# BATCH_STREAM,
		# BATCH_RR,  round-robin with a fixed number of batches?
	};

	global fast_publish_batch_policy = BATCH_EXCLUSIVE &redef;

	# Options when using PUBLISH_MODE_FAST or PUBLISH_MODE_FAST_THREAD.
	#
	# PUBLISH_MODE_FAST_THREAD always shares one batch per connection
	# and stream and keeps it open until it's committed, so it ignores
	# fast_publish_batch_policy and fast_publish_max_batch_size.

	# The requested number of messages per flow acknowledgement. The
	# server starts lower and may adjust the value at runtime, but
	# never above this one.
	#
	# nats-server (2.14, 2.15) uses at most 500 messages per flow
	# acknowledgement, divided by the number of batches publishing to
	# the stream concurrently. With PUBLISH_MODE_FAST_THREAD, larger
	# values are clamped to 500 with a warning.
	global fast_publish_flow = 100 &redef;
	global fast_publish_max_batch_size = 1000 &redef;
	global fast_publish_max_outstanding_acks = 16 &redef;

	# How long to wait for a commit. With PUBLISH_MODE_FAST_THREAD,
	# also the maximum time the publisher thread waits for a flow
	# acknowledgement. Hitting it ends the batch: messages in flight
	# then are likely stored, but their outcome is unknown. The batch
	# is committed to confirm what the server persisted, and the rest
	# are counted as publish timeouts, not publish errors. The next
	# message starts a new batch.
	#
	# Short server pauses, e.g. while a full stream deletes old blocks,
	# can exceed one second. A batch that couldn't be committed lingers
	# on the server until its batch timeout (10 seconds after its last
	# message, see the server's jetstream limits max_batch_timeout),
	# reducing the flow budget of the other batches of the stream
	# meanwhile.
	global fast_publish_commit_timeout = 5sec &redef;

	# Commit a batch when no message has been published for this long.
	# The server abandons batches after 10 seconds without traffic, so
	# keep this below that. With PUBLISH_MODE_FAST_THREAD, set to 0sec
	# to disable.
	global fast_publish_idle_timeout = 1sec &redef;

	# With PUBLISH_MODE_FAST_THREAD, each writer buffers this many
	# formatted writes and queues them at once for the publisher thread
	# of the shared batch, which publishes them in order. Buffered writes
	# are also queued on flush and with every writer heartbeat
	# (Threading::heartbeat_interval). A log flush (e.g. Log::flush())
	# also commits the shared batch once everything queued so far is
	# published, waiting up to fast_publish_commit_timeout.
	#
	# Outcomes are accounted to the writer that produced the message:
	# acks, publish errors (definite failures such as lost messages or
	# rejected batches), publish timeouts and dropped writes.
	#
	# Writers of different streams can't share a batch: the stream is
	# identified by stream_name_template, so it must name the stream the
	# writer actually publishes to, also when create_stream is F.
	global fast_publish_thread_writer_batch: count = 64 &redef;

	# With PUBLISH_MODE_FAST_THREAD, the maximum size in bytes of the
	# messages queued for a shared batch's publisher thread. This bounds
	# memory when the server can't keep up, see publish_async_no_stall.
	global fast_publish_thread_queue_size: count = 64 * 1024 * 1024 &redef;

	# With PUBLISH_MODE_FAST_THREAD and publish_async_no_stall, the
	# maximum time a writer waits for queue space before dropping its
	# buffered writes and counting them as dropped writes. This absorbs
	# short bursts without blocking log writers for long.
	global fast_publish_thread_stall_wait: interval = 50msec &redef;
}
