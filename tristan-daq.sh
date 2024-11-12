#! /bin/bash
NIC=$1
MODE=$2
PORTS=$3
DEBUG=$4

Q=2
if [ "$NIC" == "" ]; then
    echo "NIC Name is not specified"
    echo "$0 <NIC>"
    exit
fi
shift

DQDK_MODE="-m waveform -d 1500"
if [ "$MODE" == "energy-histo" ]; then
    DQDK_MODE="-m energy-histo"
fi
shift

xdp-loader unload --all $NIC
source mlx5-optimize.sh $NIC $Q

pci=`ethtool -i $NIC | grep 'bus-info:' | sed 's/bus-info: //'`

INTR_STRING=$(cat /proc/interrupts | grep ${pci} | head -${Q} | awk '{printf "%s%s", sep, substr($1, 1, length($1)-1); sep=","} END{print ""}')
if [ $Q -eq 1 ]; then
    Q_STRING=0
    ethtool --set-priv-flags $NIC rx_cqe_compress on
else
    Q_STRING=0-$(($Q - 1))
    ethtool --set-priv-flags $NIC rx_cqe_compress off
    ethtool -N $NIC rx-flow-hash udp4 sdfn
fi

mlx5-rx-dbg.sh $NIC | tee $(pwd)/ethtool.log &

PERF_EV="context-switches,cpu-migrations,cycles,mem-loads,mem-stores,ref-cycles,instructions,LLC-loads,LLC-load-misses,LLC-stores,LLC-store-misses,dTLB-load-misses,dTLB-loads,dTLB-store-misses,dTLB-stores,iTLB-load-misses,branch-instructions,branch-misses,bus-cycles"
POWER_EV="power/energy-ram/,power/energy-pkg/"

# CMD="perf record -e $PERF_EV ./dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING -G $DQDK_MODE -a $PORTS $DEBUG_ARG"
[[ "$DEBUG" == "debug" ]] && DEBUG_ARG="-D" || DEBUG_ARG=
CMD="dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING -G $DQDK_MODE -a $PORTS $DEBUG_ARG"
echo "Executing DQDK Command is: $CMD"

$CMD

pkill mlx5-rx-dbg.sh
