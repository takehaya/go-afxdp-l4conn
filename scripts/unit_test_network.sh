#!/bin/bash

#                                       ┌─────┐
#                                       │     │
# veth-h1-rt1-01─────────►veth-rt1-h1-01│     │
#                                       │     │
#                                       │     │
# veth-h1-rt1-02◄─────────veth-rt1-h1-02│     │
#                                       │     │
#                                       └─────┘
#                                         dut  

set -eu

if [[ $(id -u) -ne 0 ]] ; then
    echo "Please run with sudo"
    exit 1
fi

run () {
    echo "$@"
    "$@" || exit 1
}

create_router1 () {
    # setup namespaces
    run ip netns add host1
    run ip netns add dra1

    # setup veth peer
    run ip link add veth-h1-rt1 type veth peer name veth-rt1-h1
    run ip link set veth-h1-rt1 netns host1
    run ip link set veth-rt1-h1 netns router1

    # host1 configuraiton
    run ip netns exec host1 ip link set lo up
    run ip netns exec host1 ip addr add 10.0.1.1/32 dev lo
    run ip netns exec host1 ip addr add 172.0.1.1/24 dev veth-h1-rt1
    run ip netns exec host1 ip link set veth-h1-rt1 up
    run ip netns exec host1 ip route add 10.0.2.0/24 via 172.0.1.2
    run ip netns exec host1 ip route add 172.0.2.0/24 via 172.0.1.2

    # router1 configuration
    run ip netns exec router1 ip link set lo up
    run ip netns exec router1 ip link set veth-rt1-h1 up
    run ip netns exec router1 ip -6 addr add fc00:1::1/128 dev lo
    run ip netns exec router1 ip addr add 172.0.1.2/24 dev veth-rt1-h1

    # sysctl for router1
    ip netns exec router1 sysctl net.ipv4.conf.all.forwarding=1
    ip netns exec router1 sysctl net.ipv6.conf.all.forwarding=1
    ip netns exec router1 sysctl net.ipv4.conf.all.rp_filter=0
}

destroy_network () {
    run ip netns del router1
    run ip netns del host1
}

stop () {
    destroy_network
}


trap stop 0 1 2 3 13 14 15

# exec functions
create_router1

status=0; $SHELL || status=$?
exit $status