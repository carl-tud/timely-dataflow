#!/bin/bash
DELAY="5ms" # one way ofc
JITTER="5ms"
LOSS="0.5%"
BANDWIDTH="100mbit"

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <up [--delay 42ms] [--jitter 42ms] [--loss 42.0%] [--bandwidth 42mbit] | down>"
    exit 1
fi

command=$1
shift

# First of all, naming -- yeah whatever. It's 3:25 am and I don't give a.
PREFIX=
NODES=9
BRIDGE="${PREFIX}br0"
BASE_IP="192.168.55"
MTU=1500 

destruct() {
    ip link del dev $BRIDGE 2>/dev/null
    for i in $(seq 0 $((NODES-1))); do
        name="${PREFIX}tincan$i"

        ip netns del $name 2>/dev/null
        ip link del veth-${name}-br 2>/dev/null
    done
}

if [ "$command" = "down" ]; then
    echo "Destruction! Yeah! Who needs your $PREFIX network anyway!"
    destruct
    exit 0
elif [ "$command" = "up" ]; then
    echo "Incepting $PREFIX virtual network! Yeah!"
else
    >&2 echo "Error: unknown command '$command'. Maybe go to bed."
    exit 1
fi

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --delay)
            DELAY="$2"
            shift 2
            ;;
        --jitter)
            JITTER="$2"
            shift 2
            ;;
        --loss)
            LOSS="$2"
            shift 2
            ;;
        --bandwidth)
            BANDWIDTH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

DISTRIBUTION=
if [ "$DELAY" = "0s" ]; then
    DISTRIBUTION=
else
    DISTRIBUTION="distribution normal"
fi

echo "Have $NODES hosts, well should"
echo "mtu=$MTU delay=$DELAY loss=$LOSS bandwidth=$BANDWIDTH"

echo "[*] Cleaning whatever mess you created earlier"
destruct

echo "[*] Creating $BRIDGE bridge"
ip link add $BRIDGE type bridge
ip link set dev $BRIDGE up

for i in $(seq 0 $((NODES-1))); do
    name="${PREFIX}tincan$i"
    ip netns add $name
    ip link add veth-${name} type veth peer name veth-${name}-br
    ip link set veth-${name} netns $name
    ip link set veth-${name}-br master $BRIDGE
    ip -n $name addr add $BASE_IP.$((i+1))/24 dev veth-${name}
    ip -n $name link set veth-${name} up
    ip -n $name link set lo up
    ip link set veth-${name}-br up

    # Disable optim stuff, GRO
    ip netns exec $name ethtool -K veth-${name} gso off tso off gro off 2>/dev/null || true
    ethtool -K veth-${name}-br gso off tso off gro off 2>/dev/null || true

    ip netns exec $name tc qdisc add dev veth-${name} root netem \
        delay $DELAY $JITTER $DISTRIBUTION \
        loss $LOSS \
        rate $BANDWIDTH \
        limit 10000 # ?????
done


echo "${PREFIX}tincan0 $BASE_IP.1 ... ${PREFIX}tincan$NODES $BASE_IP.$((NODES))"
echo "Reminder:"
echo "    sudo ip netns exec ${PREFIX}tincanX ..."