#!/bin/bash

metric=size
host_name=$(uname -n)
host_arch=$(uname -m)
kernel_name=$(uname -s)
kernel_ver=$(uname -r)

TARGET_DIR="target-size"

OS="$(uname)"

size_json() {
    CARGO_TARGET_DIR=$TARGET_DIR cargo build --release $1 --example pagerank
    if [ "$OS" = "Darwin" ]; then
        size -m $TARGET_DIR/release/examples/pagerank | awk '
            /Segment __TEXT:/ { rom += $3 }
            /Segment __DATA_CONST:/ { ram += $3 }
            /Segment __LINKEDIT:/ { rom += $3 }
            /Segment __DATA:/ { ram += $3 }
            END {
                print "{ ram: " ram ", rom: " rom " }"
            }'
    else
        size $TARGET_DIR/release/examples/pagerank | awk 'NR==2 { print "{ ram: " $2 + $3 ", rom: " $1 + $2 " }" }'
    fi
}

baseline=$(size_json "")
with_shmem=$(size_json "--features shared-memory,tcp")
with_tcp=$(size_json "--features tcp")
with_tls=$(size_json "--features tls")
with_quic=$(size_json "--features quic")

cat <<EOF
{
    command: ["cargo", "build", "--release"],
    metric: "$metric",
    host: {
        name: "$host_name",
        architecture: "$host_arch",
        kernel: {
            name: "$kernel_name",
            version: "$kernel_ver"
        }
    },
    results: {
        baseline: $baseline,
        shmem: $with_shmem,
        tcp: $with_tcp,
        tls: $with_tls,
        quic: $with_quic,
    }
}
EOF