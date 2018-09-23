# udriver
small program to monitor AMP scans and capture their payloads.

Make sure to adjust your lat/long, and the subnet you wish to monitor in udriver.c

Requires libgeoip and libpcap to compile

Compile on Linux: gcc udriver.c -lGeoIP -lm -lpcap -o udriver

# Compile for MIPS via emulated MIPS on QEMU

apt-get install qemu-system-mips

wget https://people.debian.org/~aurel32/qemu/mips/debian_wheezy_mips_standard.qcow2
wget https://people.debian.org/~aurel32/qemu/mips/vmlinux-3.2.0-4-5kc-malta
qemu-img create -f qcow2 -o backing_file=debian_wheezy_mips_standard.qcow2 disk.qcow2
qemu-system-mips64 -M malta -kernel vmlinux-3.2.0-4-5kc-malta -hda disk.qcow2 -append "root=/dev/sda1 console=ttyS0 mem=256m@0x0 mem=768m@0x90000000" -nographic -m 1024 -net nic,macaddr=52:54:00:fa:ce:07,model=virtio -net user,hostfwd=tcp:127.0.0.1:2022-:22
ssh -p 2022 root@localhost

default pass is: root

apt-get install build-essential git autoconf libtool bison flex libapt-pkg-dev libboost-dev libperl-dev libboost-filesystem-dev libboost-system-dev libboost-thread-dev libpcre3-dev libgeoip-dev libgeoip1 libpcap0.8 libpcap0.8-dev

Compile: gcc -static -Wall udriver.c -lGeoIP -lm -lpcap -o udriver

# Notes
I wanted to run this on EDGE router so went about compiling a static MIPS version to put onto the router.

Example of the output: 

[2018-09-22 16:15:41] UDP AMP SCAN - Port: 1900, IP: 185.10.68.110 [DE], ASN: AS200651 FLOKINET
[2018-09-22 16:15:41] UDP AMP SCAN - Port: 1900, IP: 185.10.68.110 [DE], METADATA: - City: N/A, Region: N/A (N/A), N/A [Germany]
[2018-09-22 16:15:41] UDP AMP SCAN - Port: 1900, IP: 185.10.68.110 [DE], METADATA: - Coordinates : [51.299301, 9.491000], distance 5740.067 miles (9237.741 km), bearing 29.86 degrees
[2018-09-22 16:15:41] UDP AMP SCAN - Port: 1900, IP: 185.10.68.110 [DE], Payload (91): \x4D\x2D\x53\x45\x41\x52\x43\x48\x20\x2A\x20\x48\x54\x54\x50\x2F\x31\x2E\x31\x0D\x0A\x48\x6F\x73\x74\x3A\x32\x33\x39\x2E\x32\x35\x35\x2E\x32\x35\x35\x2E\x32\x35\x30\x3A\x31\x39\x30\x30\x0D\x0A\x53\x54\x3A\x73\x73\x64\x70\x3A\x61\x6C\x6C\x0D\x0A\x4D\x61\x6E\x3A\x22\x73\x73\x64\x70\x3A\x64\x69\x73\x63\x6F\x76\x65\x72\x22\x0D\x0A\x4D\x58\x3A\x33\x0D\x0A\x0D\x0A\x00
