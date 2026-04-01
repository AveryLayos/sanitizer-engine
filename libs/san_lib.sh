#!/bin/bash
set -o pipefail
# Configuration
RULES_FILE="./sanitizer_rules.yar"
TMP_BASE="${SANITIZER_TMP_BASE:-/tmp/sanitizer_engine}"

decode_base64_to_file() {
    local out_file="$1"

    # GNU base64 (Linux)
    if printf '' | base64 -d >/dev/null 2>&1; then
        base64 -d > "$out_file"
        return $?
    fi

    # BSD base64 (macOS)
    if printf '' | base64 -D >/dev/null 2>&1; then
        base64 -D > "$out_file"
        return $?
    fi

    # Fallback
    openssl base64 -d -A > "$out_file"
}

# --- Sanitization Functions ---
sanitize_base64() {
    # Ensure the filesystem temp base exists (macOS + Linux)
    mkdir -p "$TMP_BASE"

    local RAW_PAYLOAD="$1"
    local SAFE_JOB_ID=$2 
    local MIME=$3
    update_job_request_status "$SAFE_JOB_ID" "$STATUS_SANITIZING"

    local JOB_DIR="$(mktemp -d "${TMP_BASE%/}/job_${SAFE_JOB_ID}_XXXXXX")" || return 1

    local RAW_FILE="$JOB_DIR/raw_input"
    local CLEAN_FILE="$JOB_DIR/cleaned_output"

    # 2. Decode Base64 to filesystem temp
    if ! printf '%s' "$RAW_PAYLOAD" | decode_base64_to_file "$RAW_FILE"; then
        update_job_request_status "$SAFE_JOB_ID" "$STATUS_FAILED_SANITIZATION"
        rm -rf "$JOB_DIR"
        return 1
    fi

    # 3. YARA Security Scan
    local SCAN_LOG
    SCAN_LOG="$(yara "$RULES_FILE" "$RAW_FILE" 2>/dev/null)"

    if [ -n "$SCAN_LOG" ]; then
        echo "{\"job_id\": \"$JOB_ID\", \"status\": \"REJECTED\", \"threat\": \"$SCAN_LOG\"}"
        update_job_request_status "$SAFE_JOB_ID" "$STATUS_FAILED_SANITIZATION"
        rm -rf "$JOB_DIR"
        return 1
    fi

    # 4. Content Disarm and Reconstruction (CDR)
    case "$MIME" in
        image/jpeg|image/png)
            convert "$RAW_FILE" -strip "$CLEAN_FILE"
            ;;
        application/pdf)
            qpdf --linearize "$RAW_FILE" "$CLEAN_FILE" >/dev/null 2>&1
            ;;
        *)
            tr -d '\000-\011\013\014\016-\037' < "$RAW_FILE" > "$CLEAN_FILE"
            ;;
    esac

    local CLEAN_PAYLOAD
    CLEAN_PAYLOAD="$(base64 < "$CLEAN_FILE" | tr -d '\n')"
    echo "$CLEAN_PAYLOAD"
    update_job_request_status "$SAFE_JOB_ID" "$STATUS_SANITIZED"

    rm -rf "$JOB_DIR"
    return 0
}



sanitize_message() {
    # Ensure the filesystem temp base exists (macOS + Linux)
    mkdir -p "$TMP_BASE"

    # Input JSON from Kafka or Command Line
    local INPUT_JSON="$1"

    # 1. Parse Metadata
    local JOB_ID
    local MIME
    local RAW_PAYLOAD
    local TOPIC
    local ORIGIN
    local SOURCE
    local MSG_TYPE
    local FILE_TYPE
    local FILE_NAME

    JOB_ID="$(echo "$INPUT_JSON" | jq -r '.metadata.job_id // "unknown"')"
    TOPIC="$(echo "$INPUT_JSON" | jq -r '.metadata.topic // env.INPUT_TOPIC // "sanitizer_in"')"
    ORIGIN="$(echo "$INPUT_JSON" | jq -r '.metadata.origin // env.MESSAGE_ORIGIN // "unknown"')"
    SOURCE="$(echo "$INPUT_JSON" | jq -r '.metadata.source // env.MESSAGE_SOURCE // "sanitizer-engine"')"
    MSG_TYPE="$(echo "$INPUT_JSON" | jq -r '.metadata.type // env.MESSAGE_TYPE // "base64_payload"')"
    FILE_TYPE="$(echo "$INPUT_JSON" | jq -r '.metadata.file_type // empty')"
    FILE_NAME="$(echo "$INPUT_JSON" | jq -r '.metadata.file_name // empty')"

    RAW_PAYLOAD="$(echo "$INPUT_JSON" | jq -r '.payload')"
    update_job_request_status "$JOB_ID" "$STATUS_SANITIZING"

    # Create a job-specific isolation folder on filesystem temp
    local SAFE_JOB_ID
    SAFE_JOB_ID="$(printf '%s' "$JOB_ID" | tr -cd '[:alnum:]_.-')"
    [ -z "$SAFE_JOB_ID" ] && SAFE_JOB_ID="unknown"

    local JOB_DIR
    JOB_DIR="$(mktemp -d "${TMP_BASE%/}/job_${SAFE_JOB_ID}_XXXXXX")" || return 1

    local RAW_FILE="$JOB_DIR/raw_input"
    local CLEAN_FILE="$JOB_DIR/cleaned_output"

    # 2. Decode Base64 to filesystem temp
    if ! printf '%s' "$RAW_PAYLOAD" | decode_base64_to_file "$RAW_FILE"; then
        update_job_request_status "$JOB_ID" "$STATUS_FAILED_SANITIZATION"
        rm -rf "$JOB_DIR"
        return 1
    fi

    # Prefer file_type from metadata, fallback to MIME detection
    MIME="${FILE_TYPE:-$(file -b --mime-type "$RAW_FILE" 2>/dev/null || echo "text/plain")}"

    # 3. YARA Security Scan
    local SCAN_LOG
    SCAN_LOG="$(yara "$RULES_FILE" "$RAW_FILE" 2>/dev/null)"

    if [ -n "$SCAN_LOG" ]; then
        echo "{\"job_id\": \"$JOB_ID\", \"status\": \"REJECTED\", \"threat\": \"$SCAN_LOG\"}"
        update_job_request_status "$JOB_ID" "$STATUS_FAILED_SANITIZATION"
        rm -rf "$JOB_DIR"
        return 1
    fi

    # 4. Content Disarm and Reconstruction (CDR)
    case "$MIME" in
        image/jpeg|image/png)
            convert "$RAW_FILE" -strip "$CLEAN_FILE"
            ;;
        application/pdf)
            qpdf --linearize "$RAW_FILE" "$CLEAN_FILE" >/dev/null 2>&1
            ;;
        *)
            tr -d '\000-\011\013\014\016-\037' < "$RAW_FILE" > "$CLEAN_FILE"
            ;;
    esac

    # 5. Re-encode and rebuild JSON using kafka_lib.sh build_message
    local CLEAN_PAYLOAD
    local REBUILT_JSON
    CLEAN_PAYLOAD="$(base64 < "$CLEAN_FILE" | tr -d '\n')"

    REBUILT_JSON="$(build_message \
        "$CLEAN_PAYLOAD" \
        "$TOPIC" \
        "$ORIGIN" \
        "$SOURCE" \
        "$MSG_TYPE" \
        "$JOB_ID" \
        "$MIME" \
        "$FILE_NAME")"

    echo "$REBUILT_JSON" | jq \
        '.status = "SANITIZED" | .engine = "portable-fs"'

    # 6. Cleanup temp files immediately
    rm -rf "$JOB_DIR"
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