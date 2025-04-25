
mode=$1

NIC=enp6s0f0np0
BRIDGE=br1
IP="10.10.0.105/24"

# function cleanup {
#     ip link delete $BRIDGE
# }

case "$mode" in
    "vhost")
        TAP=dfvtap

        ip link add $BRIDGE type bridge

        ip addr flush dev $NIC
        ip link set $NIC master $BRIDGE
        ip link set dev $NIC up

        ip addr add $IP dev $BRIDGE
        ip link set $BRIDGE up
        sysctl -w net.ipv4.ip_forward=1

        ip link set dev $BRIDGE promisc on
        ip link set dev $NIC promisc on

        iptables -I FORWARD -o $BRIDGE -j ACCEPT
        iptables -I FORWARD -i $BRIDGE -j ACCEPT
        iptables -I FORWARD -i $BRIDGE -o $BRIDGE -j ACCEPT
    ;;
    
    "sriov")
        # cleanup
        NIC_VF=enp6s0f0v0
        ip a add $IP dev $NIC
        ip li set dev $NIC up

        echo 1 > /sys/class/net/$NIC/device/sriov_numvfs
        modprobe vfio-pci
        modprobe vfio_iommu_type1
        modprobe vfio

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

    "cleanup")
        # cleanup
    ;;

    *)
        echo "Invalid mode: $mode"
    ;;
esac

