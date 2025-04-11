#! /bin/bash

mode=$1
nic=$2

if [ -z "$nic" ]; then
    echo "Invalid NIC name"
    exit 1
fi

nic_numa=$(cat /sys/class/net/$nic/device/numa_node)
if [ "$nic_numa" == -1 ]; then
    nic_numa=0
fi

dqdk_proc_main=$(pgrep -wx dqdk | sort | head -n 1)
dqdk_proc_thread=$(pgrep -wx dqdk | sort | tail -n 1)
dqdk_nprocs=$(pgrep -cwx dqdk)

echo $dqdk_proc_thread
if [ -z "$dqdk_proc_thread" ]; then
    echo "Is DQDK really running?"
    exit 1
fi

if [ "$dqdk_nprocs" -gt 2 ]; then
    echo "No more than 1 DQDK process is supported"
    exit 1
fi

function annoy_smp() {
    cpumap=$(cat /sys/devices/system/node/node$nic_numa/cpumap | sed 's/,/ /g')
    while kill -0 "$dqdk_proc_thread" 2>/dev/null; do
        for i in $(cat /sys/devices/system/node/node0/cpulist | sed 's/,/ /g'); do
            if ! kill -0 "$dqdk_proc_thread" 2>/dev/null; then
                break
            fi
            taskset -cp $i $dqdk_proc_thread
            taskset -c $i apt update > /dev/null 2>&1
            sleep 1
        done
    done
    echo "Process Exited"
}

function annoy_numa() {
    numas=$(awk -F: '/physical id/ {print $2}' /proc/cpuinfo | sort -un | grep -v "^ $nic_numa$" | sed 's/ //g' | head -n 1)
    if kill -0 "$dqdk_proc_thread" 2>/dev/null; then
        cpu=$(cat /sys/devices/system/node/node$numas/cpulist | sed 's/,/\n/g' | head -n 1)
        taskset -cp $cpu $dqdk_proc_thread
        migratepages $dqdk_proc_main $nic_numa $numas
    else
        echo "Process Exited"
    fi
}

case "$mode" in
    "smp")
        annoy_smp
        exit 0
    ;;

    "numa")
        annoy_numa
        exit 0
    ;;

    *)
        echo "Unknown annoy mode"
        exit 1
esac
