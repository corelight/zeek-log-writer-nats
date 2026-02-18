FROM zeek/zeek:8.0

RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential \
	ca-certificates \
	cmake \
	curl \
	libpcap-dev \
	libssl-dev \
	libnats-dev \
	unzip

# Install nats, nats-server
WORKDIR /opt/nats/tmp
COPY docker/install-nats.sh .
RUN ./install-nats.sh /opt/nats/bin
ENV PATH=/opt/nats/bin:$PATH
RUN nats --version
RUN nats-server --version

# Build and install zeek-nats plugin
WORKDIR /zeek-nats
RUN git config --global --add safe.directory $(pwd)
COPY ./ .
RUN ./configure && make
RUN ZEEK_PLUGIN_PATH=./build zeek -N Zeek::NATS
