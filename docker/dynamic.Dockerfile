FROM ubuntu:18.04

RUN apt update && apt install -y software-properties-common \
    build-essential libssl-dev curl \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && curl -sL https://apt.kitware.com/keys/kitware-archive-latest.asc \
    | apt-key add - \
    && apt-add-repository -y 'deb https://apt.kitware.com/ubuntu/ bionic main' \
    && apt update \
    && apt install -y gcc-11 g++-11 cmake \
    && update-alternatives \
    --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-11 \
    --slave /usr/bin/gcov gcov /usr/bin/gcov-11
