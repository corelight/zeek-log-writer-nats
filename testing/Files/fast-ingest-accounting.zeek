# Helpers for fast-ingest tests: write n log records and report each
# writer's outcome counters, checking that every write is accounted.

module FastIngestTest;

export {
	type Info: record {
		n: count &log;
	};

	## Writes per log path.
	global written: table[string] of count &default=0;

	## Write n records to the stream with the given path.
	global write: function(id: Log::ID, path: string, n: count);

	## Print each writer's counters and whether acks, errors, timeouts,
	## dropped writes and pending add up to its writes.
	global report: function();
}

function write(id: Log::ID, path: string, n: count)
	{
	local i = 0;
	while ( i < n )
		{
		Log::write(id, [$n=written[path] + i]);
		++i;
		}

	written[path] += n;
	}

function report()
	{
	local values: table[string, string] of double;
	local paths: set[string];
	local sorted: vector of string;

	for ( _, m in Telemetry::collect_metrics("zeek_nats_log_writer_backend*", "*") )
		{
		local name = sub(m$opts$name, /zeek_nats_log_writer_backend_/, "");
		values[m$label_values[1], name] = m$value;
		add paths[m$label_values[1]];
		}

	for ( p in paths )
		sorted += p;

	sort(sorted, strcmp);

	for ( _, p in sorted )
		{
		local acks = values[p, "publish_acks_total"];
		local errors = values[p, "publish_errors_total"];
		local timeouts = values[p, "publish_timeouts_total"];
		local dropped = values[p, "dropped_writes_total"];
		local pending = values[p, "publishes_pending"];
		print fmt("%s written=%d acks=%.0f errors=%.0f timeouts=%.0f dropped=%.0f pending=%.0f accounted=%s",
		          p, written[p], acks, errors, timeouts, dropped, pending,
		          acks + errors + timeouts + dropped + pending == written[p]);
		}
	}
