#!/bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi
     #rx_queue_0_packets: 72223795
     #rx_queue_0_bytes: 4333427830
     #rx_queue_0_drops: 104446
     #rx_queue_0_xdp_packets: 21757254
     #rx_queue_0_xdp_tx: 0
     #rx_queue_0_xdp_redirects: 21648455
     #rx_queue_0_xdp_drops: 104446

rx_xsk_packets=0
rx_xsk_xdp_redirect=0
rx_xdp_drop=0
rx_packets_phy=0

while sleep 1; do
    values_now=$(ethtool -S $NIC | grep -w "rx_queue_0_packets\|rx_queue_0_xdp_packets\|rx_queue_0_xdp_redirects\|rx_queue_0_xdp_drops" | awk '{print $2}' ORS=' ')
    rx_xsk_packets_now=$(echo $values_now | awk '{print $2}')
    rx_xdp_drop_now=$(echo $values_now | awk '{print $4}')
    rx_xsk_xdp_redirect_now=$(echo $values_now | awk '{print $3}')
    rx_packets_phy_now=$(echo $values_now | awk '{print $1}')

    rx_pps=$((rx_xsk_packets_now - rx_xsk_packets))
    rx_rdr=$((rx_xsk_xdp_redirect_now - rx_xsk_xdp_redirect))
    if [[ "$rx_rdr" -gt "0" ]]; then
        rx_xdp_drp=$((rx_xdp_drop_now - rx_xdp_drop))
        rx_phy=$((rx_packets_phy_now - rx_packets_phy))
        columns="PPS,Phy PPS,Redirects,XDP Drop"
        echo -e "$rx_pps\t\t$rx_phy\t\t$rx_rdr\t\t$rx_xdp_drp\t\t" | column --table --table-columns "$columns" --output-separator "|"
    fi

    rx_xsk_packets=$rx_xsk_packets_now
    rx_xsk_xdp_redirect=$rx_xsk_xdp_redirect_now
    rx_xdp_drop=$rx_xdp_drop_now
    rx_packets_phy=$rx_packets_phy_now
done
