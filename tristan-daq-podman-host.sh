#! /bin/bash
NIC=$1
MODE=$2
PORTS=$3
DEBUG=$4

Q=3
if [[ "$#" -lt 3 ]]; then
    echo "$0: Incorrect number of parameters!"
    echo "$0 <NIC> <tristan-mode> <udp-port-range> [debug]"
    exit
fi

DQDK_MODE="-m $MODE -d 2000"

nic_numa=$(cat /sys/class/net/$NIC/device/numa_node)
if [[ "$nic_numa" == "-1" ]]; then
    nic_numa=0
fi

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
power_start=$(cat /sys/class/powercap/intel-rapl:0/energy_uj)
$CMD
power_end=$(cat /sys/class/powercap/intel-rapl:0/energy_uj)
echo "Energy Consumption (microjoules):" $((power_end - power_start))

pkill mlx5-rx-dbg.sh
