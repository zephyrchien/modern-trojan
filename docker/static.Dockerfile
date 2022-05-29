FROM alpine:edge AS buildssl

RUN apk add --no-cache linux-headers build-base perl curl \
    && curl -sL https://www.openssl.org/source/old/1.1.1/openssl-1.1.1n.tar.gz|tar -zx \
    && cd openssl-1.1.1n \
    && ./config no-shared -static \
    && make -j \
    && make test \
    && make install_sw 


FROM alpine:edge

COPY --from=buildssl /usr/local/include/openssl /usr/include/openssl
COPY --from=buildssl /usr/local/lib/libcrypto.a /usr/lib/libcrypto.a
COPY --from=buildssl /usr/local/lib/libssl.a /usr/lib/libssl.a

RUN apk update && apk add --no-cache linux-headers build-base cmake
