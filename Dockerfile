FROM fedora:24

RUN dnf install -y llvm clang kernel-devel make binutils

RUN mkdir -p /src

WORKDIR /src
