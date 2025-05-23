#! /bin/bash
set -e

if [ "$1" = "" ]; then
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

NIC=$1
queues=1
pci=`ethtool -i $NIC | grep 'bus-info:' | sed 's/bus-info: //'`

if [[ "$2" != "" ]]; then
    queues=$2
fi

echo "Setting MTU..."
ip link set dev $NIC mtu 9000
ethtool -s $NIC speed 100000
max_hw_rxq=`ethtool -g $NIC | grep -m 1 RX: | awk '{print $2}'`
# max_hw_txq=`ethtool -g $NIC | grep -m 1 TX: | awk '{print $2}'`

echo "ethtool-based Optimizations"
echo "ethtool -G" ; ethtool -G $NIC rx $max_hw_rxq
echo "ethtool -L" ; ethtool -L $NIC combined $queues
# ethtool -K $NIC gro off rx-fcs off sg off tx-ipxip4-segmentation off rx-checksumming off tx-checksumming off \
# tx-udp-segmentation off gso off rx-gro-list off tso off tx-ipxip6-segmentation off \
# tx-udp_tnl-csum-segmentation off hw-tc-offload off rx-vlan-stag-filter off \
# rx-udp-gro-forwarding off tx off tx-nocache-copy off tx-udp_tnl-segmentation off \
# lro off rx-udp_tunnel-port-offload off tx-checksum-ip-generic off \
# tx-scatter-gather off tx-vlan-stag-hw-insert off ntuple on rx-vlan-filter off \
# tx-gre-csum-segmentation off tx-tcp-mangleid-segmentation off txvlan off rx off \
# rxhash on tx-gre-segmentation off tx-tcp-segmentation off rx-all off rxvlan off \
# tx-gso-partial off tx-tcp6-segmentation off rx-checksumming off tx-checksumming off macsec-hw-offload off
# ethtool --set-priv-flags $NIC rx_cqe_moder off rx_striding_rq off rx_no_csum_complete off xdp_tx_mpwqe off skb_tx_mpwqe off

echo "Optimizing Virtual Memory Usage..."
sysctl -w vm.zone_reclaim_mode=0
sysctl -w vm.swappiness=0

# echo "Optimizing busy poll parameters..."
# echo 2 > /sys/class/net/$NIC/napi_defer_hard_irqs
# echo 200000 > /sys/class/net/$NIC/gro_flush_timeout

# ht=`cat /sys/devices/system/cpu/smt/active`
# if [ "$ht" = "1" ]; then
#     echo "Hyper-threading is enabled!"
#     read -p "Disable Hyperthreading? [y/n]..." answer
#     if [ "$answer" = "y" ]; then
#         echo off > /sys/devices/system/cpu/smt/control
#     fi
# else
#     echo "Hyper-threading is disabled!"
# fi

# echo "Disabling Real-time Throttling..."
# echo -1 > /proc/sys/kernel/sched_rt_runtime_us
# echo -1 > /proc/sys/kernel/sched_rt_period_us
