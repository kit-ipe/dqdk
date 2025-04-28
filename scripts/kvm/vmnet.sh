
mode=$1

NIC=enp6s0f0np0
BRIDGE=br1
IP="10.10.0.105/24"
TAP=dfvtap

# function cleanup {
#     ip link delete $BRIDGE
# }

case "$mode" in
    "vhost")
        ip link add $BRIDGE type bridge

        ip addr flush dev $NIC
        ip link set dev $NIC master $BRIDGE mtu 9000 promisc on up

        ip addr add $IP dev $BRIDGE
        ip link set $BRIDGE promisc on up
        sysctl -w net.ipv4.ip_forward=1

        iptables -I FORWARD -o $BRIDGE -j ACCEPT
        iptables -I FORWARD -i $BRIDGE -j ACCEPT
        iptables -I FORWARD -i $BRIDGE -o $BRIDGE -j ACCEPT
    ;;
    
    "sriov")
        NIC_VF=enp6s0f0v0
        if [ -d /sys/class/net/$BRIDGE ]; then
            echo "Removing bridge..."
            ip li set dev $NIC down
            ip link delete $BRIDGE
        fi

        if [ -d /sys/class/net/$TAP ]; then
            echo "Removing TAP interface..."
            ip link delete $TAP
        fi

        ip a add $IP dev $NIC
        ip li set dev $NIC mtu 3498 up

        echo 1 > /sys/class/net/$NIC/device/sriov_numvfs
        modprobe vfio-pci
        modprobe vfio_iommu_type1
        modprobe vfio

        ip li set dev $NIC vf 0 mac 32:43:ab:3a:07:28
        pci=$(ethtool -i $NIC_VF | grep 'bus-info:' | sed 's/bus-info: //')
        devid=$(lspci -nn -s $pci | sed -n 's/.*\[\([^]]*\):\([^]]*\)\].*/\1 \2/p')
        echo "Unbinding device driver: $pci $NIC_VF [$devid]"
        echo $pci > /sys/bus/pci/devices/${pci}/driver/unbind
        echo "Binding to vfio-pci..."
        # echo $devid > /sys/bus/pci/drivers/vfio-pci/new_id
        echo "vfio-pci" > /sys/bus/pci/devices/$pci/driver_override
        echo $pci > /sys/bus/pci/drivers/vfio-pci/bind
        lspci -nnk -s $pci
    ;;

    *)
        echo "Invalid mode: $mode"
    ;;
esac

