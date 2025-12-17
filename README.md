# Zeek Log Writer NATS

Provides a Zeek log writer implementation for the [NATS.io Connective Technology](https://nats.io/)
[JetStream](https://docs.nats.io/nats-concepts/jetstream) persistence system.

## Requirements and Installation

This plugin has a build dependency on the [nats.c](https://github.com/nats-io/nats.c) client library.
The build system automatically detects whether the library was installed via apt or vcpkg,
and both produce identical builds.

**Using apt (Debian/Ubuntu):**

```bash
$ apt-get update && apt-get install libnats-dev
$ ./configure && make
$ sudo make install
```

**Using vcpkg:**

```bash
$ vcpkg install cnats
$ ./configure && make
$ sudo make install
```

The build will first look for the system `libnats-dev` library. If not found, it falls back
to vcpkg's `cnats` package.

```bash
$ vcpkg install cnats
$ ./configure && make
$ sudo make install
```

The build will first look for the system `libnats-dev` library. If not found, it falls back
to vcpkg's `cnats` package.

## Testing

After compiling and installing the plugin, verify Zeek is able to load the plugin:

```bash
$ zeek -NN Zeek::Log_Writer_NATS
Zeek::Log_Writer_NATS - Log writer sending to NATS (dynamic, version 0.0.6)
    [Writer] NATS (Log::WRITER_NATS)
```

Testing against a locally running NATS server can be done as follows:

Start a NATS server in one terminal, by default it'll listen on port 4222 which
is also used in the plugin by default.

```bash
$ nats-server -js
```

Change the `Log::default_writer` of Zeek to `Log::WRITER_NATS` and listen on an interface:

```bash
$ zeek -C -i lo Log::default_writer=Log::WRITER_NATS
```

In yet another terminal, subscribe to the default subject used by the plugin,
using the `nats` CLI. This will show all logs produced by the Zeek instance.

```bash
$ nats subscribe 'sensor.logs.*'
17:51:56 Subscribing on sensor.logs.*
[#1] Received on "sensor.logs.conn" with reply "_INBOX.9X1BKP55Y367UVU5Q31QM4.32"
{"ts":1708620711.443446,"uid":"Cbsjg31hoFHw6fkJch","id.orig_h":"172.17.0.2","id.orig_p":47476,"id.resp_h":"192.0.78.212","id.resp_p":443,"proto":"tcp","service":"ssl","duration":2.2717180252075195,"orig_bytes":758,"resp_bytes":86930,"conn_state":"SF","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADadFf","orig_pkts":48,"orig_ip_bytes":2698,"resp_pkts":48,"resp_ip_bytes":88862}

```
