#!/bin/bash
set -o pipefail
# Configuration
RULES_FILE="./sanitizer_rules.yar"
RAM_BASE="/dev/shm/sanitizer_engine"

# --- Sanitization Functions ---
sanitize_message() {

    # Ensure the RAM base directory exists
    mkdir -p "$RAM_BASE"

    # Input JSON from Kafka or Command Line
    local INPUT_JSON="$1"

    # 1. Parse Metadata
    local JOB_ID
    local MIME
    local RAW_PAYLOAD

    JOB_ID="$(echo "$INPUT_JSON" | jq -r '.metadata.job_id // "unknown"')"
    MIME="$(echo "$INPUT_JSON" | jq -r '.content_type // "text/plain"')"
    RAW_PAYLOAD="$(echo "$INPUT_JSON" | jq -r '.payload')"
    echo "Processing Job ID: $JOB_ID with MIME type: $MIME"
    echo "jobid: $JOB_ID, status: $STATUS_SANITIZING, mime: $MIME"
    update_job_request_status "$JOB_ID" "$STATUS_SANITIZING"
    # Create a job-specific isolation folder in RAM
    local JOB_DIR="$RAM_BASE/job_$JOB_ID"
    local RAW_FILE="$JOB_DIR/raw_input"
    local CLEAN_FILE="$JOB_DIR/cleaned_output"

    mkdir -p "$JOB_DIR"

    # 2. Decode Base64 to RAM
    echo "$RAW_PAYLOAD" | base64 -d > "$RAW_FILE"

    # 3. YARA Security Scan
    # Note: yara returns 0 if matches are found. We check the output.
    local SCAN_LOG
    SCAN_LOG="$(yara "$RULES_FILE" "$RAW_FILE" 2>/dev/null)"

    if [ -n "$SCAN_LOG" ]; then
        echo "{\"job_id\": \"$JOB_ID\", \"status\": \"REJECTED\", \"threat\": \"$SCAN_LOG\"}"
        echo update_job_request_status "$JOB_ID" "$STATUS_FAILED_SANITIZATION"
        update_job_request_status "$JOB_ID" "$STATUS_FAILED_SANITIZATION"
        rm -rf "$JOB_DIR"
        exit 1
    fi

    # 4. Content Disarm and Reconstruction (CDR)
    case "$MIME" in
        image/jpeg|image/png)
            # Use ImageMagick to strip non-pixel data (EXIF, hidden tags)
            convert "$RAW_FILE" -strip "$CLEAN_FILE"
            ;;
        application/pdf)
            # Flatten and linearize PDF structure
            qpdf --linearize --replace-input "$RAW_FILE" --out "$CLEAN_FILE" > /dev/null 2>&1
            ;;
        *)
            # Default: Strip null bytes and control characters from text/CSVs
            tr -d '\000-\011\013\014\016-\037' < "$RAW_FILE" > "$CLEAN_FILE"
            ;;
    esac

    # 5. Re-encode and Return JSON
    # Keep the base64 string on a single line for JSON compatibility
    local CLEAN_PAYLOAD
    CLEAN_PAYLOAD="$(base64 < "$CLEAN_FILE" | tr -d '\n')"

    echo "$INPUT_JSON" | jq \
        --arg p "$CLEAN_PAYLOAD" \
        '.payload = $p | .status = "SANITIZED" | .engine = "rocky-linux-shm"'

    # 6. Cleanup RAM immediately
    rm -rf "$JOB_DIR"
    echo update_job_request_status "$JOB_ID" "$STATUS_SANITIZED"
    update_job_request_status "$JOB_ID" "$STATUS_SANITIZED"
    return 0
}

sanitize_pcap() {
    local in="$1"
    local out="$OUTPUT_DIR/$(basename "$1")"

    # -s 96 truncates the payload, keeping only headers (Ethernet/IP/TCP)
    # This removes PII/Data while preserving flow for anomaly detection
    tcpdump -r "$in" -w "$out" -s 96 2>/dev/null
    echo "[+] PCAP sanitized (Payloads stripped): $out"
}

sanitize_text() {
    local in="$1"
    local out="$OUTPUT_DIR/$(basename "$1")"

    # 1. Strip CR characters to prevent Log Injection
    # 2. Mask IPv4 addresses (Example: 192.168.x.x -> 192.168.MASK.MASK)
    # 3. Remove known sensitive keywords (case-insensitive)
    sed -E 's/([0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}/\1.XXX.XXX/g' "$in" | \
        sed -E 's/(password|passwd|token|auth|secret)=[^ ]*/\1=REDACTED/gI' | \
        tr -d '\r' > "$out"

    echo "[+] Text log sanitized: $out"
}

sanitize_json() {
    local in="$1"
    local out="$OUTPUT_DIR/$(basename "$1")"

    # Use jq to recursively delete sensitive keys regardless of depth
    jq 'walk(if type == "object" then del(.password, .token, .secret, .sessionID) else . end)' "$in" > "$out"
    echo "[+] JSON sanitized (Keys removed): $out"
}