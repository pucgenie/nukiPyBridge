# Pull base image
FROM python:2.7.13-stretch
MAINTAINER Gert-Jan Compagner

# Install dependencies
RUN apt-get update && apt-get install -y \
    vim \
    gcc \
    build-essential \
    libglib2.0-dev \
    bluez \
    libbluetooth-dev \
    libffi-dev \
libusb-dev \
libdbus-1-dev \
libglib2.0-dev \
libudev-dev \
libical-dev \
libreadline-dev \
    libboost-python-dev \
    git \ 
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

RUN pip install pygatt
RUN pip install pynacl
RUN pip install crc16
RUN pip install pybluez
RUN pip install pexpect
RUN apt-get update && apt-get install -y wget

RUN mkdir /tmp/bluez
RUN wget http://www.kernel.org/pub/linux/bluetooth/bluez-5.51.tar.xz -O /tmp/bluez/bluez-5.51.tar.xz
WORKDIR /tmp/bluez
RUN tar xvf bluez-5.51.tar.xz 
WORKDIR /tmp/bluez/bluez-5.51
RUN ./configure --disable-systemd
RUN make
RUN make install

# fix library problem for python3 & libboost
#RUN mv /usr/lib/arm-linux-gnueabihf/libboost_python-py27.so.1.55.0 /usr/lib/arm-linux-gnueabihf/libboost_python-py27.so.1.55.0-old
#RUN ln -s /usr/lib/arm-linux-gnueabihf/libboost_python-py34.so.1.55.0 /usr/lib/arm-linux-gnueabihf/libboost_python-py27.so.1.55.0

COPY gatttool.py /usr/local/lib/python2.7/dist-packages/pygatt/backends/gatttool/gatttool.py
COPY . /opt/nuki

RUN pip install flask

ENV FLASK_APP server.py

WORKDIR /opt/nuki 

CMD ["flask", "run", "-h", "0.0.0.0"]
