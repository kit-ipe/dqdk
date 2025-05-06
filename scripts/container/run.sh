#! /bin/bash
NIC=$1
NETWORK=$2

NIC=enp6s0f0np0
BRIDGE=br1
IP="10.10.0.105/24"

case $NETWORK in
    bridge)
        if podman network exists dqdk-net; then
            podman network rm -f dqdk-net
        fi

        ip link add $BRIDGE mtu 3498 type bridge

        ip addr flush dev $NIC
        ip link set dev $NIC master $BRIDGE mtu 3498 promisc on up

        ip addr add $IP dev $BRIDGE
        ip link set $BRIDGE promisc on up
        sysctl -w net.ipv4.ip_forward=1

        iptables -I FORWARD -o $BRIDGE -j ACCEPT
        iptables -I FORWARD -i $BRIDGE -j ACCEPT
        iptables -I FORWARD -i $BRIDGE -o $BRIDGE -j ACCEPT
        podman network create --driver bridge --interface-name=$BRIDGE --subnet=10.20.0.0/24 dqdk-net
        NETWORK="dqdk-net"
        ;;

    host)
    ;;

    *)
        echo "Invalid network type."
        exit 1
    ;;
esac

nic_numa=$(cat /sys/class/net/$NIC/device/numa_node)
if [[ "$nic_numa" == "-1" ]]; then
    nic_numa=0
fi

echo 2048 > /sys/devices/system/node/node${nic_numa}/hugepages/hugepages-2048kB/nr_hugepages

podman run --name dqdk-container \
    --mount type=bind,source=/home/jalal/dqdk,target=/dqdk \
    --memory=0 \
    --memory-swap=-1 \
    --ulimit memlock=-1:-1 \
    --cpuset-mems=0 \
    --cpuset-cpus=0,4,8,12,16,20,24,28 \
    --cpu-quota=-1 \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --cap-add=BPF \
    --cap-add=SYS_ADMIN \
    --cap-add=PERFMON \
    --cap-add=IPC_LOCK \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_NICE \
    --rm -it dqdk
    # --network=$NETWORK \

echo 0 > /sys/devices/system/node/node${nic_numa}/hugepages/hugepages-2048kB/nr_hugepages
