#!/bin/bash

run_pagerank() {
    tools/benchmark.sh \
        --iterations 10 \
        --parallel $1 \
        --metric time \
        --output target/bench-pagerank-50-100-${1}p-${2}t-10x-ipc-local-time-riot:uuid.json \
        -- \
        target/release/examples/pagerank 50 100 \
        --threads $2 \
        --processes :n \
        --process :i \
        --sharedmemory
}

for i in $(seq 1 8);
do
    threads=$((64 / $i))
    processes=$i
    echo "Running pagerank with 64 workers in $threads threads across $processes processes..."
    run_pagerank $processes $threads
done

# Same number of workers, but distribution onto threads/processes different

# workers threads processes constant: TCP vs ICP
# workers threads processes constant: TCP vs TLS vs QUIC

# 