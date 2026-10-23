#!/bin/bash
#
# Build and install nats.c and orbit.c's jetstream-extra into $1. orbit.c
# requires a newer nats.c than distributions ship.
set -eux

NATS_C_VERSION=v3.14.0
ORBIT_C_COMMIT=899b01c8644d850ec5a6de56f714f7ee76fbb967

PREFIX=$1
PATCHES=$(cd "$(dirname "$0")" && pwd)/patches

git clone --depth 1 --branch ${NATS_C_VERSION} https://github.com/nats-io/nats.c
cmake -S nats.c -B nats.c/build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} \
    -DNATS_BUILD_STREAMING=OFF \
    -DNATS_BUILD_EXAMPLES=OFF \
    -DBUILD_TESTING=OFF
cmake --build nats.c/build -j "$(nproc)"
cmake --install nats.c/build

git clone https://github.com/synadia-io/orbit.c
git -C orbit.c checkout ${ORBIT_C_COMMIT}
for p in "${PATCHES}"/orbit-*.patch; do
    git -C orbit.c apply --verbose "$p"
done
cmake -S orbit.c -B orbit.c/build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} \
    -DCMAKE_PREFIX_PATH=${PREFIX} \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DORBIT_BUILD_LIB_SHARED=OFF \
    -DBUILD_TESTING=OFF
cmake --build orbit.c/build -j "$(nproc)"
cmake --install orbit.c/build

ldconfig
