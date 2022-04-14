FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get -yq install python3 python3-setuptools python3-pip wget fakeroot gnupg2 libglib2.0-bin file \
 desktop-file-utils libgdk-pixbuf2.0-dev librsvg2-dev libyaml-dev zsync gtk-update-icon-cache strace elfutils

ADD . /opt/appimage-builder

WORKDIR /opt/appimage-builder
RUN python3 ./setup.py install && rm -rf /opt/appimage-builder

RUN wget https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage -O /opt/appimagetool \
    && chmod +x /opt/appimagetool \
    && cd /opt/; sed -i 's|AI\x02|\x00\x00\x00|' appimagetool; /opt/appimagetool --appimage-extract \ 
    && mv /opt/squashfs-root /opt/appimagetool.AppDir \
    && ln -s /opt/appimagetool.AppDir/AppRun /usr/local/bin/appimagetool

WORKDIR /tmp
RUN wget https://github.com/NixOS/patchelf/releases/download/0.12/patchelf-0.12.tar.bz2; \
    tar -xvf patchelf-0.12.tar.bz2;  \
    cd patchelf-0.12.20200827.8d3a16e; \
    ./configure && make && make install; \
    rm -rf patchelf-*

WORKDIR /
RUN apt-get -yq autoclean
