#! /bin/bash
NIC=$1
MODE=$2
PORTS=$3
DEBUG=$4

Q=1
if [[ "$#" -lt 3 ]]; then
    echo "$0: Incorrect number of parameters!"
    echo "$0 <NIC> <tristan-mode> <udp-port-range> [debug]"
    exit
fi

DQDK_MODE="-m $MODE -d 2000"

if [[ -f /sys/class/net/$NIC/device/numa_node ]]; then
	nic_numa=$(cat /sys/class/net/$NIC/device/numa_node)
	if [[ "$nic_numa" == "-1" ]]; then
        nic_numa=0
	fi
else
	nic_numa=0
fi

echo 0 > /sys/devices/system/node/node${nic_numa}/hugepages/hugepages-2048kB/nr_hugepages

xdp-loader unload --all $NIC
source virtio-optimize.sh $NIC $Q


pci=`ethtool -i $NIC | grep 'bus-info:' | sed 's/bus-info: //'`
if [ $pci != "0000:01:00.0" ]; then
    echo "Please use 0000:01:00.0 PCI Address inside guest machine for the $NIC. Current=$pci"
    exit 1
fi
INTR_STRING=$(cat /proc/interrupts | grep "virtio1-input" | head -${Q} | awk '{printf "%s%s", sep, substr($1, 1, length($1)-1); sep=","} END{print ""}')

if [ $Q -eq 1 ]; then
    Q_STRING=0
else
    Q_STRING=0-$(($Q - 1))
    ethtool -N $NIC rx-flow-hash udp4 sdfn
fi

virtio-rx-dbg.sh $NIC | tee $(pwd)/ethtool.log &

PERF_EV="context-switches,cpu-migrations,cycles,mem-loads,mem-stores,ref-cycles,instructions,LLC-loads,LLC-load-misses,LLC-stores,LLC-store-misses,dTLB-load-misses,dTLB-loads,dTLB-store-misses,dTLB-stores,iTLB-load-misses,branches,branch-instructions,branch-misses,bus-cycles,page-faults,L1-icache-load-misses,L1-dcache-loads,L1-dcache-load-misses"
POWER_EV="power/energy-ram/,power/energy-pkg/,power/energy-psys/"
echo "mode" $DQDK_MODE
case "$DEBUG" in
    "profile")
        CMD="perf stat -e $PERF_EV dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING $DQDK_MODE -a $PORTS -G"
        ;;
    
    "power")
        CMD="perf stat -e $POWER_EV dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING $DQDK_MODE -a $PORTS -G"
        ;;

    "latency")
        CMD="dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING $DQDK_MODE -a $PORTS -G -D"
        ;;

    "latency-profile")
        CMD="perf stat -e $PERF_EV dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING $DQDK_MODE -a $PORTS -G -D"
        ;;

    "latency-dump")
        CMD="dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING $DQDK_MODE -a $PORTS -G -D -l"
        ;;

    "")
        CMD="dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING $DQDK_MODE -a $PORTS -G"
        ;;
    *)
        echo "Invalid profile: $DEBUG"
        exit 0
esac

echo "Executing DQDK Command is: $CMD"
$CMD

pkill virtio-rx-dbg.sh
