#!/bin/bash

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults
iterations=""
parallel=""
metric=""
output_template=""
command_args=()

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --iterations)
            iterations="$2"
            shift 2
            ;;
        --parallel)
            parallel="$2"
            shift 2
            ;;
        --metric)
            metric="$2"
            shift 2
            ;;
        --output)
            output_template="$2"
            shift 2
            ;;
        --)
            # Stop parsing arguments, the rest is the command
            shift
            command_args=("$@")
            break
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$iterations" || -z "$parallel" || -z "$metric" || ${#command_args[@]} -eq 0 ]]; then
    echo "Usage: $0 --iterations <N> --parallel <N> --metric <time|memory> [--output <file>] -- <command>"
    exit 1
fi

final_cmd=("${command_args[@]}")

# If metric is memory, wrap the command with memory.sh
# Note: We add the '--' separator as requested in the memory spec
if [[ "$metric" == "memory" ]]; then
    final_cmd=("$TOOLS_DIR/memory.sh" "--" "${final_cmd[@]}")
fi

final_cmd=("$TOOLS_DIR/parallel.sh" "$parallel" "--" "${final_cmd[@]}")
final_cmd=("$TOOLS_DIR/iter.sh" "$iterations" "$metric" "--" "${final_cmd[@]}")

if [[ -n "$output_template" ]]; then
    # Generate UUID (platform independent)
    if command -v uuidgen &> /dev/null; then
        my_uuid=$(uuidgen)
    else
        # Fallback for Linux environments without uuidgen
        my_uuid=$(cat /proc/sys/kernel/random/uuid)
    fi

    # Replace :uuid placeholder with the actual UUID
    output_file="${output_template//:uuid/$my_uuid}"

    "${final_cmd[@]}" > "$output_file"
else
    exec "${final_cmd[@]}"
fi