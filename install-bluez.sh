mkdir -p /tmp/bluez/bluez-5.51
wget "http://www.kernel.org/pub/linux/bluetooth/bluez-5.51.tar.xz" -O /tmp/bluez/bluez-5.51.tar.xz
tar xvf /tmp/bluez/bluez-5.51.tar.xz -C /tmp/bluez/
cd /tmp/bluez/bluez-5.51
/tmp/bluez/bluez-5.51/configure
make  -C /tmp/bluez/bluez-5.51
sudo make install -C /tmp/bluez/bluez-5.51
sudo systemctl daemon-reload
sudo systemctl start bluetooth
sudo systemctl enable bluetooth
sudo nano /lib/systemd/system/bluetooth.service
# add ExecStart=/usr/local/libexec/bluetooth/bluetoothd --experimental  
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
