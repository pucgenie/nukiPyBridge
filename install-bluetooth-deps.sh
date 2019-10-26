sudo apt-get update && sudo apt-get install -y \
    gcc \
    build-essential \
    libglib2.0-dev \
    libbluetooth-dev \
    libffi-dev \
    libusb-dev \
    libdbus-1-dev \
    libglib2.0-dev \
    libudev-dev \
    libical-dev \
    supervisor \
    libreadline-dev \
    libboost-python-dev \
    && rm -rf /var/lib/apt/lists/*

sudo python -m easy_install --upgrade pygatt pynacl crc16 pybluez pexpect flask

./install-bluez.sh

sudo cp gatttool.py /usr/local/lib/python2.7/dist-packages/pygatt/backends/gatttool/gatttool.py

sudo cp nuki-supervised.conf /etc/supervisor/conf.d/nuki.conf
