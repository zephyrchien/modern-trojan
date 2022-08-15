# Modern Trojan

Trojan written in modern C++(>=20).

## Usage

```bash
trojan -l <addr> -p <port> -k <password> -a <cert> -b <key>

OPTIONS:
    -d              daemonize
    -n <nofile>     set nofile limit
```

## Build

### Requirements

- gcc >= 11 / clang >= 13

- openssl 1.1.1

- cmake >= 3.19

- asio >= 1.22

- fmt

- range-v3

Clone this repository:

```shell
git clone https://github.com/zephyrchien/modern-trojan

cd modern-trojan
```

Install dependencies with `vcpkg`:

```shell
git clone https://github.com/microsoft/vcpkg
vcpkg/bootstrap-vcpkg.sh
vcpkg/vcpkg integrate install
vcpkg/vcpkg install asio
vcpkg/vcpkg install fmt
vcpkg/vcpkg install range-v3
```

Generate makefile and build:

```shell
mkdir build && cd build

cmake ..

make -j
```

Strip symbols:

```shell
strip trojan
```

*Note: libgcc/libstdc++ are statically-linked. To have them dynamically-linked you can add `-DSTATIC_STD=OFF` when generating the makefile.

## Build-static

To build a pure statically linked binary, we need to link trojan against musl-libc, instead of glibc. And we also need to build openssl as a static library (libssl.a, libcrypto.a).

We can have these things done smoothly with the help of docker containers. See `docker/static.Dockerfile`.

Setup build environment:

```shell
docker build . -t build-static -f static.Dockerfile
```

Enter docker container(share this folder):

```shell
docker run -it -v "${PWD}":"/trojan" /bin/sh
```

Generate makefile and build:

```shell
mkdir build-musl && cd build-musl

cmake -DSTATIC_BIN ..

make -j
```

Strip symbols:

```shell
strip trojan
```

Or combine these commands in one line:

```shell
docker run --rm -it -v "${PWD}":"/trojan" \
    build-static \
    sh -c "cd trojan && mkdir build-musl && cd build-musl
    && cmake -DSTATIC_BIN ..
    && make -j
    && strip trojan"
```
