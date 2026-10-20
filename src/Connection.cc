#include "Connection.h"

#include <nats/nats.h>

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

Connection::Connection(ConnectionOptions opts) : opts(std::move(opts)) {}

Connection::~Connection() {
    if ( natsConn )
        natsConnection_Destroy(natsConn);
}

Result Connection::ConnectRaw() {
    if ( natsConn )
        return Ok();

    natsStatus s;
    natsOptions* natsOpts = nullptr;

    if ( s = natsOptions_Create(&natsOpts); s != NATS_OK )
        return Error("Could not create options");

    if ( s = natsOptions_SetURL(natsOpts, opts.url.c_str()); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        natsOptions_Destroy(natsOpts);
        return Error("Failed to SetURL: " + error);
    }

    if ( s = natsConnection_Connect(&natsConn, natsOpts); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        natsOptions_Destroy(natsOpts);
        return Error("Failed to connect to " + opts.url + ": " + error);
    }

    natsOptions_Destroy(natsOpts);

    return Ok();
}

Result Connection::JetStream(jsCtx** js, int64_t publish_async_max_pending, int64_t publish_async_stall_wait_ms,
                             jsPubAckHandler ack_handler, void* ack_handler_closure) {
    natsStatus s;
    jsOptions jsOpts;

    if ( s = jsOptions_Init(&jsOpts); s != NATS_OK ) {
        *js = nullptr;
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to init JetStream options: " + error);
    }

    jsOpts.PublishAsync.MaxPending = publish_async_max_pending;
    jsOpts.PublishAsync.StallWait = publish_async_stall_wait_ms;
    jsOpts.PublishAsync.AckHandler = ack_handler;
    jsOpts.PublishAsync.AckHandlerClosure = ack_handler_closure;

    if ( s = natsConnection_JetStream(js, natsConn, &jsOpts); s != NATS_OK ) {
        *js = nullptr;
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to initialize JetStream: " + error);
    }

    return Ok();
}

Result ExclusiveConnection::Connect() {
    // ExclusiveConnection just connects.
    return ConnectRaw();
}

std::shared_ptr<Connection> ExclusiveConnectionFactory::Create(std::string url) {
    ConnectionOptions opts = {
        .url = std::move(url),
    };
    return std::make_shared<ExclusiveConnection>(std::move(opts));
}


Result SharedConnection::Connect() {
    // Connect() may be called by multiple threads
    // at the same time, protect ConnectRaw().
    std::scoped_lock lock{connect_mutex};
    return ConnectRaw();
}


std::shared_ptr<Connection> SharedConnectionFactory::Create(std::string url) {
    // Lock the full connection table. Creating a connection
    // shouldn't be done very often, so this should be fine.
    std::shared_ptr<Connection> conn;
    std::scoped_lock lock{connections_mtx};
    auto it = connections.find(url);
    if ( it != connections.end() ) {
        std::weak_ptr<Connection> c = it->second;
        conn = c.lock();
        if ( conn )
            return conn;
    }

    // Alright, a new connection is needed.
    ConnectionOptions opts = {
        .url = url,
    };
    conn = std::make_shared<SharedConnection>(std::move(opts));

    // Keep a weak-pointer for this connection around.
    connections[url] = conn;

    return conn;
}


// Just two global instances in the detail namespace for now.
ExclusiveConnectionFactory zeek::plugin::Zeek_Log_Writer_NATS::detail::factory_exclusive;
SharedConnectionFactory zeek::plugin::Zeek_Log_Writer_NATS::detail::factory_shared;
