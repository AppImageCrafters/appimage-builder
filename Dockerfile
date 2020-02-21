FROM ubuntu:bionic

RUN apt-get update
RUN apt-get -y install python3 python3-setuptools python3-pip wget patchelf fakeroot gnupg2 libglib2.0-bin file desktop-file-utils

ADD . /tmp/sources

WORKDIR /tmp/sources
RUN python3 ./setup.py install

WORKDIR /
RUN cd /tmp && wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
RUN chmod +x /tmp/appimagetool-x86_64.AppImage

RUN cd opt && /tmp/appimagetool-x86_64.AppImage --appimage-extract

RUN ln -s /opt/squashfs-root/AppRun /usr/bin/appimagetool

RUN rm /tmp/appimagetool-x86_64.AppImage
RUN apt-get -y purge wget
RUN apt-get -y autoclean
