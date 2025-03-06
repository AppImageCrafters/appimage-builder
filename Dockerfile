FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -yq install \
    breeze-icon-theme \
    desktop-file-utils \
    elfutils \
    fakeroot \
    file \
    git \
    gnupg2 \
    gtk-update-icon-cache \
    libgdk-pixbuf2.0-dev \
    libglib2.0-bin \
    librsvg2-dev \
    libyaml-dev \
    python3 \
    python3-pip \
    squashfs-tools \
    strace \
    wget \
    zsync && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN wget https://github.com/NixOS/patchelf/releases/download/0.12/patchelf-0.12.tar.bz2; \
    tar -xvf patchelf-0.12.tar.bz2;  \
    cd patchelf-0.12.20200827.8d3a16e; \
    ./configure && make && make install; \
    rm -rf patchelf-*

COPY . /opt/appimage-builder
RUN python3 -m pip install setuptools==75.3.0 && \
    python3 -m pip install /opt/appimage-builder && \
    rm -rf /opt/appimage-builder

WORKDIR /
