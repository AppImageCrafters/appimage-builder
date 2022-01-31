FROM ubuntu:18.04

RUN apt-get update && apt-get -y install python3 python3-setuptools python3-pip wget fakeroot gnupg2 libglib2.0-bin file \
 desktop-file-utils libgdk-pixbuf2.0-dev librsvg2-dev libyaml-dev zsync gtk-update-icon-cache strace elfutils

ADD . /opt/appimage-builder

WORKDIR /opt/appimage-builder
RUN python3 ./setup.py install && rm -rf /opt/appimage-builder

WORKDIR /tmp
RUN wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage && \
    chmod +x /tmp/appimagetool-x86_64.AppImage && \
    cd /opt && /tmp/appimagetool-x86_64.AppImage --appimage-extract && \
    mv squashfs-root appimage-tool.AppDir && \
    ln -s /opt/appimage-tool.AppDir/AppRun /usr/bin/appimagetool && \
    rm /tmp/appimagetool-x86_64.AppImage

RUN wget https://github.com/NixOS/patchelf/releases/download/0.12/patchelf-0.12.tar.bz2; \
    tar -xvf patchelf-0.12.tar.bz2;  \
    cd patchelf-0.12.20200827.8d3a16e; \
    ./configure && make && make install; \
    rm -rf patchelf-*

WORKDIR /
RUN apt-get -y autoclean
