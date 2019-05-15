# udriver
small program to monitor AMP scans and capture their payloads.

Make sure to adjust your lat/long, and the subnet you wish to monitor in udriver.c

Requires libgeoip and libpcap to compile

Compile on Linux: gcc udriver.c -lGeoIP -lm -lpcap -o udriver

will need to load the geoip databases used /GeoIP you can adjust the source if you want to point to some other path.
```
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
```
# Compile for MIPS via emulated MIPS on QEMU

apt-get install qemu-system-mips
```
wget https://people.debian.org/~aurel32/qemu/mips/debian_wheezy_mips_standard.qcow2
wget https://people.debian.org/~aurel32/qemu/mips/vmlinux-3.2.0-4-5kc-malta
qemu-img create -f qcow2 -o backing_file=debian_wheezy_mips_standard.qcow2 disk.qcow2
qemu-system-mips64 -M malta -kernel vmlinux-3.2.0-4-5kc-malta -hda disk.qcow2 -append "root=/dev/sda1 console=ttyS0 mem=256m@0x0 mem=768m@0x90000000" -nographic -m 1024 -net nic,macaddr=52:54:00:fa:ce:07,model=virtio -net user,hostfwd=tcp:127.0.0.1:2022-:22
ssh -p 2022 root@localhost
```
default pass is: root
```
apt-get install build-essential git autoconf libtool bison flex libapt-pkg-dev libboost-dev libperl-dev libboost-filesystem-dev libboost-system-dev libboost-thread-dev libpcre3-dev libgeoip-dev libgeoip1 libpcap0.8 libpcap0.8-dev
```
Compile: gcc -static -Wall udriver.c -lGeoIP -lm -lpcap -o udriver


