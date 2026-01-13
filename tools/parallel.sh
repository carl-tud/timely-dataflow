#!/bin/bash
# Gemini has assisted the creation of this script

count=$1
shift

if [ "$1" == "--" ]; then
    shift
fi

trap 'echo "Stopping..."; kill $(jobs -p); exit' SIGINT

for ((i=0; i<count; i++)); do
    # Build the specific command for this instance
    instance_cmd=()
    for arg in "$@"; do
        # Replace :n with the total number
        arg="${arg//:n/$count}"
        # Replace :i with the current iteration (0 to N-1)
        arg="${arg//:i/$i}"
        instance_cmd+=("$arg")
    done

    # Execute in background
    "${instance_cmd[@]}" &
done

wait
echo "All processes finished."