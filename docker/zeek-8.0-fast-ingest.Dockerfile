FROM zeek/zeek:8.0

# No libnats-dev, nats.c is built from source for orbit.c.
RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential \
	ca-certificates \
	cmake \
	curl \
	git \
	libpcap-dev \
	libssl-dev \
	unzip

# Install nats, nats-server
WORKDIR /opt/nats/tmp
COPY docker/install-nats.sh .
RUN ./install-nats.sh /opt/nats/bin
ENV PATH=/opt/nats/bin:$PATH
RUN nats --version
RUN nats-server --version

# Install nats.c and orbit.c
WORKDIR /opt/orbit/tmp
COPY docker/install-orbit.sh .
COPY docker/patches ./patches
RUN ./install-orbit.sh /usr/local

# Build and install zeek-nats plugin
WORKDIR /zeek-nats
RUN git config --global --add safe.directory $(pwd)
COPY ./ .
RUN ./configure && make
RUN ZEEK_PLUGIN_PATH=./build zeek -N Zeek::Log_Writer_NATS
