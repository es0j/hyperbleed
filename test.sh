#!/bin/bash 

echo "Run with ./test.sh <sibling-core> | tee results/<machine-name>.txt"

echo "/proc/cpuinfo:"
cat /proc/cpuinfo

echo "/etc/lsb-release:"
cat /etc/lsb-release

echo "/etc/os-release:"
cat /etc/os-release

echo "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list:"
cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list

echo "/etc/default/grub:"
cat /etc/default/grub

make
kill -9 $(pidof attacker)
sudo ./spectre-meltdown-checker.sh 

echo -e "\nStarting attacker on core 0: "
./attacker 0x55555554123 0x55555555345 0 &



echo -e "\nTesting victim on core 0: "
(time ./victim 0x55555554123 0x55555555345 0)  |& tee /dev/null

echo -e "\nTesting victim on core $1: "
(time ./victim 0x55555554123 0x55555555345 $1) |& tee /dev/null

echo "--------------------------------------------"

echo -e "\nTesting victim-nospecctrl on core 0: "
(time ./victim-nospecctrl 0x55555554123 0x55555555345 0) |& tee /dev/null

echo -e "\nTesting victim-nospecctrl on core $1: "
(time ./victim-nospecctrl 0x55555554123 0x55555555345 $1) |& tee /dev/null

echo "--------------------------------------------"

echo -e "\nTesting victim-IBRS on core 0: "
(time ./victim-IBRS 0x55555554123 0x55555555345 0) |& tee /dev/null

echo -e "\nTesting victim-IBRS on core $1: "
(time ./victim-IBRS 0x55555554123 0x55555555345 $1) |& tee /dev/null

echo "--------------------------------------------"

echo -e "\nTesting victim-STIBP on core 0: "
(time ./victim-STIBP 0x55555554123 0x55555555345 0) |& tee /dev/null

echo -e "\nTesting victim-STIBP on core $1: "
(time ./victim-STIBP 0x55555554123 0x55555555345 $1) |& tee /dev/null

echo "--------------------------------------------"

echo -e "\nTesting victim-IBPB on core 0: "
(time ./victim-IBPB 0x55555554123 0x55555555345 0)  |& tee /dev/null

echo -e "\nTesting victim-IBPB on core $1: "
(time ./victim-IBPB 0x55555554123 0x55555555345 $1) |& tee /dev/null

echo "--------------------------------------------"

echo -e "\nTesting victim-PRCTL on core 0: "
(time ./victim-PRCTL 0x55555554123 0x55555555345 0) |& tee /dev/null

echo -e "\nTesting victim-PRCTL on core $1: "
(time ./victim-PRCTL 0x55555554123 0x55555555345 $1) |& tee /dev/null

echo -e "\nkilling attacker"
kill -9 $(pidof attacker)

make clean

sudo dmesg