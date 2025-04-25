#!/bin/bash

echo "=== Bridge Diagnostic Script ==="

IF="enp6s0f0np0"
TAP="dfvtap"
BRIDGE="br1"
VM_IP="10.10.0.106"
EXT_IP="10.10.0.104"
HOST_IP="10.10.0.105"

echo -e "\n🧱 Bridge Status:"
brctl show $BRIDGE || echo "❌ Bridge $BRIDGE not found"

echo -e "\n🌐 Interface IPs:"
echo "- $BRIDGE: $(ip -4 addr show $BRIDGE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
echo "- $IF: $(ip -4 addr show $IF | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"

echo -e "\n🔌 Bridge Members:"
bridge link | grep "$BRIDGE"

echo -e "\n📶 Interface States:"
for iface in $BRIDGE $IF $TAP ; do
    echo "- $iface: $(ip link show $iface 2>/dev/null | grep -o 'state UP' || echo 'DOWN or not found')"
done

echo -e "\n🔎 Promiscuous Mode:"
for iface in $BRIDGE $IF $TAP; do
    [ -e /sys/class/net/$iface/flags ] && \
    (($(cat /sys/class/net/$iface/flags) & 0x100)) && echo "- $iface: ✅ promisc on" || echo "- $iface: ❌ promisc off"
done

echo -e "\n🧪 Pinging from host ($HOST_IP)..."
ping -c 3 $EXT_IP && echo "✅ Host can reach external" || echo "❌ Host cannot reach external"
ping -c 3 $VM_IP && echo "✅ Host can reach VM" || echo "❌ Host cannot reach VM"

echo -e "\n✅ Recommended Fixes:"
echo "- Ensure eth0 has NO IP address (only br0 should)"
echo "- Check that $IF and $TAP are added to $BRIDGE"
echo "- Enable promisc mode if needed"
echo "- Ensure no firewall is blocking bridge traffic"

