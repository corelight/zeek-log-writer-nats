FROM zeek/zeek:9.0

RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential \
	ca-certificates \
	cmake \
	curl \
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

# Compile libnats/nats.c and install.
WORKDIR /libnats
COPY 3rdparty/nats.c ./
RUN \
  rm -rf ./build \
  && mkdir build \
  && cd build \
  && cmake ../ \
  && make -j \
  && make install

# Build and install zeek-nats plugin
WORKDIR /zeek-nats
COPY ./ .
RUN ./configure && make
RUN ZEEK_PLUGIN_PATH=./build zeek -N Zeek::Log_Writer_NATS
