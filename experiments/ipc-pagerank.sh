#!/bin/bash

iterations=5
HOSTFILE=experiments/ipc-hosts.txt

if [ "$(uname)" = "Darwin" ]; then
    TARGET_DIR="target-mac"
else
    TARGET_DIR="target"
fi

# mac: max 5000000 20000000

# [time|memory] nodes edges processes threads
run_pagerank_threads() {
    tools/benchmark.sh \
        --iterations $iterations \
        --parallel 1 \
        --metric $1 \
        --output experiments/results/ipc-pagerank-${2}n-${3}e-1pr-${5}th-${iterations}x-${1}-$(uname)-$(uname -m)-:uuid.json \
        -- \
        $TARGET_DIR/release/examples/pagerank $2 $3 \
        --threads $5 \
        --processes :n \
        --process :i
}

# [time|memory] nodes edges processes threads
run_pagerank_shmem() {
    tools/benchmark.sh \
        --iterations $iterations \
        --parallel $4 \
        --metric $1 \
        --output experiments/results/ipc-pagerank-${2}n-${3}e-${4}pr-${5}th-${iterations}x-shmem-${1}-$(uname)-$(uname -m)-:uuid.json \
        -- \
        $TARGET_DIR/release/examples/pagerank $2 $3 \
        --threads $5 \
        --processes :n \
        --process :i \
        --hostfile $HOSTFILE \
        --sharedmemory
}

# [time|memory] nodes edges processes threads [tcp|tls|quic]
run_pagerank_transport() {
    tools/benchmark.sh \
        --iterations $iterations \
        --parallel $4 \
        --metric $1 \
        --output experiments/results/ipc-pagerank-${2}n-${3}e-${4}pr-${5}th-${iterations}x-${6}-${1}-$(uname)-$(uname -m)-:uuid.json \
        -- \
        $TARGET_DIR/release/examples/pagerank $2 $3 \
        --threads $5 \
        --processes :n \
        --process :i \
        --hostfile $HOSTFILE \
        --transport $6

}

DEGREE=16

echo "localhost:2101
localhost:2102" > $HOSTFILE
cat $HOSTFILE

# 1000 10000 100000 1000000
for nodes in 1000000; do
    edges=$((nodes * DEGREE))
    echo "Testing nodes=$nodes, edges=$edges"
    
    echo "Threads"
    run_pagerank_threads time $nodes $edges 1 2
    echo "IPC shared memory"
    run_pagerank_shmem time $nodes $edges 2 1
    echo "IPC TCP"
    run_pagerank_transport time $nodes $edges 2 1 tcp
    echo "IPC TLS"
    run_pagerank_transport time $nodes $edges 2 1 tls
    echo "IPC QUIC"
    run_pagerank_transport time $nodes $edges 2 1 quic
done