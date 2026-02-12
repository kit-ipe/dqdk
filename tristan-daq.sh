#! /bin/bash
NIC=$1
MODE=$2
PORTS=$3
DURATION=$4
PAYLOADSZ=$5
DQDK_ID=1
PROFILE=$6

DQDK_BIN=/home/jalal/dqdk/src/dqdk
BASE_DIR=/mnt/raid0
BATCH_SIZE=2048

Q=3
if [[ "$#" -lt 3 ]]; then
    echo "$0: Incorrect number of parameters!"
    echo "$0 <NIC> <tristan-mode> <udp-port-range> [duration] [profile]"
    exit
fi

if [ -z $DURATION ]; then
    DURATION=0
fi

if [ -z $PAYLOADSZ ]; then
    PAYLOADSZ=3392
    echo "Using default payload size: $PAYLOADSZ"
fi

DQDK_MODE="-m $MODE"

nic_numa=$(cat /sys/class/net/$NIC/device/numa_node)
if [[ "$nic_numa" == "-1" ]]; then
    nic_numa=0
fi

echo 0 > /sys/devices/system/node/node${nic_numa}/hugepages/hugepages-2048kB/nr_hugepages

ip link set dev $NIC up
xdp-loader unload --all $NIC
source mlx5-optimize.sh $NIC $Q

pci=`ethtool -i $NIC | grep 'bus-info:' | sed 's/bus-info: //'`
INTR_STRING=$(cat /proc/interrupts | grep "mlx5_comp[0-9]*@pci:${pci}" | head -${Q} | awk '{printf "%s%s", sep, substr($1, 1, length($1)-1); sep=","} END{print ""}')

if [ $Q -eq 1 ]; then
    Q_STRING=0
else
    Q_STRING=0-$(($Q - 1))
    ethtool -N $NIC rx-flow-hash udp4 sdfn
fi

mlx5-rx-dbg.sh $NIC | tee $(pwd)/ethtool.log &

PERF_EV="context-switches,cpu-migrations,cycles,mem-loads,mem-stores,ref-cycles,instructions,LLC-loads,LLC-load-misses,LLC-stores,LLC-store-misses,dTLB-load-misses,dTLB-loads,dTLB-store-misses,dTLB-stores,iTLB-load-misses,branches,branch-instructions,branch-misses,bus-cycles,page-faults,L1-icache-load-misses,L1-dcache-loads,L1-dcache-load-misses"
POWER_EV="power/energy-ram/,power/energy-pkg/,power/energy-psys/"

case "$PROFILE" in
    "profile")
        CMD="perf record -e $PERF_EV $DQDK_BIN -i $NIC -d $DURATION -q $Q_STRING -b $BATCH_SIZE -I $DQDK_ID -A $INTR_STRING $DQDK_MODE -a $PORTS -G -P $BASE_DIR -s $PAYLOADSZ"
        ;;
    
    "power")
        CMD="perf stat -e $POWER_EV $DQDK_BIN -i $NIC -d $DURATION -q $Q_STRING -b $BATCH_SIZE -I $DQDK_ID -A $INTR_STRING $DQDK_MODE -a $PORTS -G -P $BASE_DIR -s $PAYLOADSZ"
        ;;

    "latency")
        CMD="$DQDK_BIN -i $NIC -d $DURATION -q $Q_STRING -b $BATCH_SIZE -A $INTR_STRING $DQDK_MODE -I $DQDK_ID -a $PORTS -G -D -P $BASE_DIR -s $PAYLOADSZ"
        ;;

    "latency-profile")
        CMD="perf stat -e $PERF_EV $DQDK_BIN -i $NIC -d $DURATION -q $Q_STRING -b $BATCH_SIZE -I $DQDK_ID -A $INTR_STRING $DQDK_MODE -a $PORTS -G -D -P $BASE_DIR -s $PAYLOADSZ"
        ;;

    "latency-dump")
        CMD="$DQDK_BIN -i $NIC -d $DURATION -q $Q_STRING -b $BATCH_SIZE -A $INTR_STRING $DQDK_MODE -I $DQDK_ID -a $PORTS -G -D -l -P $BASE_DIR -s $PAYLOADSZ"
        ;;

    "strip-wfm")
        CMD="$DQDK_BIN -i $NIC -q $Q_STRING -d $DURATION -b $BATCH_SIZE -A $INTR_STRING $DQDK_MODE -I $DQDK_ID -a $PORTS -G -P $BASE_DIR -s $PAYLOADSZ -W"
        ;;

    "")
        CMD="$DQDK_BIN -i $NIC -q $Q_STRING -d $DURATION -b $BATCH_SIZE -A $INTR_STRING $DQDK_MODE -I $DQDK_ID -a $PORTS -G -P $BASE_DIR -s $PAYLOADSZ"
        ;;
    *)
        echo "Invalid profile: $PROFILE"
        exit 0
esac

echo "Executing DQDK Command is: $CMD"
power_start=$(cat /sys/class/powercap/intel-rapl:0/energy_uj)
$CMD
power_end=$(cat /sys/class/powercap/intel-rapl:0/energy_uj)
echo "Energy Consumption (microjoules):" $((power_end - power_start))
pkill mlx5-rx-dbg.sh
