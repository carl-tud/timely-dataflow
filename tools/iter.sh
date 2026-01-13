#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <iterations> <metric: time|memory> <command...>"
    exit 1
fi

iterations=$1
metric=$2
shift 2

if [ "$1" == "--" ]; then
    shift
fi

command_args=("$@")

json_command="["
for arg in "${command_args[@]}"; do
    safe_arg=$(echo "$arg" | sed 's/"/\\"/g')
    json_command+="\"$safe_arg\", "
done
json_command="${json_command%, }]"

# 2. Adjust Command based on Metric
# if [ "$metric" == "memory" ]; then
#     # Prepend ./memory.sh to the command arguments
#     # We assume ./memory.sh handles the command execution and outputs the metrics
#     run_cmd=("./memory.sh" "${command_args[@]}")
# else
#     run_cmd=("${command_args[@]}")
# fi

run_cmd=("${command_args[@]}")

time_runs=""
mem_hv_runs=""
mem_hr_runs=""
mem_sv_runs=""
mem_sr_runs=""

extract_values() {
    local raw_output="$1"
    local key="$2"
    # grep finds lines, cut gets value, paste joins them with commas
    echo "$raw_output" | grep -oE "${key}=[0-9]+" | cut -d= -f2 | paste -sd, -
}

format_array() {
    local vals="$1"
    if [ -z "$vals" ]; then
        echo "[]"
    else
        echo "[$vals]"
    fi
}

for ((i=0; i<iterations; i++)); do
    output=$("${run_cmd[@]}" 2>&1)
    
    if [ "$metric" == "time" ]; then
        # Parse Duration
        vals=$(extract_values "$output" "duration_us")
        time_runs+="$(format_array "$vals"), "
        
    elif [ "$metric" == "memory" ]; then
        # Parse Heap Virtual
        hv=$(extract_values "$output" "memory_heap_virtual_bytes")
        mem_hv_runs+="$(format_array "$hv"), "
        
        # Parse Heap Resident
        hr=$(extract_values "$output" "memory_heap_resident_bytes")
        mem_hr_runs+="$(format_array "$hr"), "
        
        # Parse Stack Virtual
        sv=$(extract_values "$output" "memory_stack_virtual_bytes")
        mem_sv_runs+="$(format_array "$sv"), "
        
        # Parse Stack Resident
        sr=$(extract_values "$output" "memory_stack_resident_bytes")
        mem_sr_runs+="$(format_array "$sr"), "
    fi
done

# Clean trailing commas
time_runs="${time_runs%, }"
mem_hv_runs="${mem_hv_runs%, }"
mem_hr_runs="${mem_hr_runs%, }"
mem_sv_runs="${mem_sv_runs%, }"
mem_sr_runs="${mem_sr_runs%, }"

if [ "$metric" == "time" ]; then
    results_json="{
        duration: [$time_runs]
    }"
elif [ "$metric" == "memory" ]; then
    results_json="{
        heap: {
            virtual: [$mem_hv_runs],
            resident: [$mem_hr_runs]
        },
        stack: {
            virtual: [$mem_sv_runs],
            resident: [$mem_sr_runs]
        }
    }"
else
    results_json="{}"
fi

host_name=$(uname -n)
host_arch=$(uname -m)
kernel_name=$(uname -s)
kernel_ver=$(uname -r)

cat <<EOF
{
    command: $json_command,
    metric: "$metric",
    host: {
        name: "$host_name",
        architecture: "$host_arch",
        kernel: {
            name: "$kernel_name",
            version: "$kernel_ver"
        }
    },
    results: $results_json
}
EOF