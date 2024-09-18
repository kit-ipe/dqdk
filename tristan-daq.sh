#! /bin/bash
NIC=$1
MODE=$2
DEBUG=$3

Q=2
if [ "$NIC" == "" ]; then
    echo "NIC Name is not specified"
    echo "$0 <NIC>"
    exit
fi
shift

DQDK_MODE="-M waveform"
if [ "$MODE" == "energy-histo" ]; then
    DQDK_MODE="-M energy-histo"
fi
shift

DIR=`dirname $0`
echo $DIR
source ${DIR}/scripts/mlx5-optimize.sh $NIC $Q

INTR_STRING=$(cat /proc/interrupts | grep mlx5 | head -${Q} | awk '{printf "%s%s", sep, substr($1, 1, length($1)-1); sep=","} END{print ""}')
if [ $Q -eq 1 ]; then
    Q_STRING=0
    ethtool --set-priv-flags $NIC rx_cqe_compress on
else
    Q_STRING=0-$(($Q - 1))
    ethtool --set-priv-flags $NIC rx_cqe_compress off
    ethtool -N $NIC rx-flow-hash udp4 sdfn
fi

${DIR}/scripts/mlx5-rx-dbg.sh $NIC | tee ethtool.log &

PERF_EV="context-switches,cpu-migrations,cycles,mem-loads,mem-stores,ref-cycles,instructions,LLC-loads,LLC-load-misses,LLC-stores,LLC-store-misses,dTLB-load-misses,dTLB-loads,dTLB-store-misses,dTLB-stores,iTLB-load-misses,branch-instructions,branch-misses,bus-cycles"

pushd ${DIR}/src
#CMD="perf stat -e $PERF_EV ./dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING -G -w $DQDK_MODE"
[[ "$DEBUG" == "debug" ]] && DEBUG_ARG="-D" || DEBUG_ARG=
CMD="./dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING -G -w $DQDK_MODE $DEBUG_ARG"
echo "Executing DQDK Command is: $CMD"

$CMD
popd

pkill mlx5-rx-dbg.sh
