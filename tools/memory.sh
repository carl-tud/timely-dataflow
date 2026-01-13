if [ "$1" == "--" ]; then
    shift
fi

command_args=("$@")
"${command_args[@]}" &
PID=$!

OS="$(uname)"

if [ "$OS" = "Linux" ]; then
    # --- Linux Implementation (smaps) ---
    awk -v pid="$PID" '
    BEGIN {
        h_virt=0; h_res=0; s_virt=0; s_res=0
        current_region="none"
    }
    # 1. Identify Region
    /^[0-9a-f]+/ {
        if ($0 ~ /\[heap\]/) { current_region="heap" }
        else if ($0 ~ /\[stack\]/) { current_region="stack" }
        else { current_region="none" }
    }
    # 2. Sum Metrics (Size=Virtual, Rss=Resident)
    /^Size:/ && current_region == "heap"  { h_virt += $2 }
    /^Rss:/  && current_region == "heap"  { h_res += $2 }
    /^Size:/ && current_region == "stack" { s_virt += $2 }
    /^Rss:/  && current_region == "stack" { s_res += $2 }
    
    END {
        print "memory_heap_virtual_bytes=" h_virt * 1024
        print "memory_heap_resident_bytes=" h_res * 1024
        print "memory_stack_virtual_bytes=" s_virt * 1024
        print "memory_stack_resident_bytes=" s_res * 1024
    }
    ' "/proc/$PID/smaps" #2>/dev/null

elif [ "$OS" = "Darwin" ]; then
    # --- macOS Implementation (vmmap) ---

    vmmap -summary "$PID" 2>/dev/null | awk '
    
    # Helper: Convert 16K, 10M, 1G to bytes
    function parse_bytes(val) {
        gsub(/[^0-9.KMG]/, "", val) # Clean string
        mult=1
        if (val ~ /K$/) mult=1024
        else if (val ~ /M$/) mult=1024*1024
        else if (val ~ /G$/) mult=1024*1024*1024
        gsub(/[KMG]$/, "", val)     # Remove suffix
        return int(val * mult)
    }

    BEGIN {
        h_virt=0; h_res=0; s_virt=0; s_res=0
        in_summary=0
    }
    
    # Start processing only after we hit the summary table header
    /^REGION TYPE/ { in_summary=1; next }
    
    in_summary == 1 {
        # Check if line matches Heap (MALLOC) or Stack
        is_heap = ($0 ~ /^MALLOC/)
        is_stack = ($0 ~ /^Stack/)
        
        if (is_heap || is_stack) {
            virt_found=0
            
            # Iterate through fields to find the first size-like string (e.g. 128K, 10.1M)
            for (i=2; i<=NF; i++) {
                if ($i ~ /^[0-9.]+[KMG]$/) {
                    # Found Virtual Size (First number)
                    v_bytes = parse_bytes($i)
                    
                    # The next field is immediately Resident Size
                    r_bytes = parse_bytes($(i+1))
                    
                    if (is_heap) {
                        h_virt += v_bytes
                        h_res += r_bytes
                    } else {
                        s_virt += v_bytes
                        s_res += r_bytes
                    }
                    virt_found=1
                    break
                }
            }
        }
    }
    
    END {
        print "memory_heap_virtual_bytes=" h_virt
        print "memory_heap_resident_bytes=" h_res
        print "memory_stack_virtual_bytes=" s_virt
        print "memory_stack_resident_bytes=" s_res
    }
    '
else
    echo "Error: Unsupported Operating System."
    exit 1
fi