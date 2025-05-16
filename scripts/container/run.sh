#! /bin/bash
NIC=$1
NETWORK=$2

NIC=enp6s0f0np0
BRIDGE=br1
IP="10.10.0.105/24"

case $NETWORK in
    bridge)
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

echo 24000 > /sys/devices/system/node/node${nic_numa}/hugepages/hugepages-2048kB/nr_hugepages

podman run --name dqdk-container \
    --mount type=bind,source=/dev/hugepages,target=/dev/hugepages \
    --memory=0 \
    --memory-swap=-1 \
    --ulimit memlock=-1:-1 \
    --cpuset-mems=0 \
    --cpuset-cpus=0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88,92,96,100,104,108,112,116,120,124 \
    --cpu-quota=-1 \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --cap-add=BPF \
    --cap-add=SYS_ADMIN \
    --cap-add=PERFMON \
    --cap-add=IPC_LOCK \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_NICE \
    --privileged \
    --network=$NETWORK \
    --rm -it dqdk

echo 0 > /sys/devices/system/node/node${nic_numa}/hugepages/hugepages-2048kB/nr_hugepages
