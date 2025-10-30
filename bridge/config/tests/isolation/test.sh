#!/bin/bash
# recreate_nuclear_lab.sh

echo "🚀 БЫСТРОЕ СОЗДАНИЕ ПОЛИГОНА ЗАНОВО"

# Создаем namespace
ip netns add nuclear_test

# Создаем минимальные интерфейсы
ip link add veth_bridge type veth peer name veth_bridge_ns
ip link add veth_attacker type veth peer name veth_attacker_ns

# Перемещаем
ip link set veth_bridge_ns netns nuclear_test
ip link set veth_attacker_ns netns nuclear_test

# Настраиваем в namespace
ip netns exec nuclear_test ip link set lo up
ip netns exec nuclear_test ip link set veth_bridge_ns up
ip netns exec nuclear_test ip link set veth_attacker_ns up

# Bridge
ip netns exec nuclear_test ip link add name nuclear_br type bridge
ip netns exec nuclear_test ip link set nuclear_br up
ip netns exec nuclear_test ip link set veth_bridge_ns master nuclear_br
ip netns exec nuclear_test ip link set veth_attacker_ns master nuclear_br

# IP адреса
ip netns exec nuclear_test ip addr add 10.200.1.1/24 dev nuclear_br
ip netns exec nuclear_test ip addr add 10.200.1.10/24 dev veth_bridge_ns
ip netns exec nuclear_test ip addr add 10.200.1.20/24 dev veth_attacker_ns

# Поднимаем внешние
ip link set veth_bridge up
ip link set veth_attacker up

echo "✅ ПОЛИГОН СОЗДАН!"
echo "🔧 Bridge: 10.200.1.1"
echo "🎯 Attacker: 10.200.1.20"
echo "🔧 Bridge endpoint: 10.200.1.10"