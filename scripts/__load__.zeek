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
