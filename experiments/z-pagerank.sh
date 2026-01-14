#!/bin/bash

iterations=10
parallel=1
threads=4

if [ "$(uname)" = "Darwin" ]; then
    TARGET_DIR="target-mac"
else
    TARGET_DIR="target"
fi

run_pagerank() {
    tools/benchmark.sh \
        --iterations $iterations \
        --parallel $parallel \
        --metric $1 \
        --output experiments/results/z0-pagerank-${parallel}pr-${threads}th-${iterations}x-${1}-$(uname)-$(uname -m)-:uuid.json \
        -- \
        $TARGET_DIR/release/examples/pagerank 900000 9000000 \
        --threads $threads \
        --processes :n \
        --process :i
}

run_pagerank_with_zerocopy() {
    tools/benchmark.sh \
        --iterations $iterations \
        --parallel $parallel \
        --metric $1 \
        --output experiments/results/z1-pagerank-${parallel}pr-${threads}th-${iterations}x-${1}-$(uname)-$(uname -m)-:uuid.json \
        -- \
        $TARGET_DIR/release/examples/pagerank 900000 9000000 \
        --threads $threads \
        --processes :n \
        --process :i \
        --zerocopy
}

run_with_and_without_zerocopy() {
    run_pagerank $1
    run_pagerank_with_zerocopy $1
}

run_with_and_without_zerocopy time
run_with_and_without_zerocopy memory