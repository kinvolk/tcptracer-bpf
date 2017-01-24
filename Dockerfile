FROM fedora:24

# vim-common is needed for xxd
# vim-minimal needs to be updated first to avoid a RPM conflict on man1/vim.1.gz
RUN dnf update -y vim-minimal && \
	dnf install -y llvm clang kernel-devel make binutils vim-common

RUN mkdir -p /src

WORKDIR /src
