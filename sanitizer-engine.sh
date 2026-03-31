#!/bin/bash
# filepath: /Users/zler/sanitizer-engine/sanitizer-engine.sh
set -o pipefail

MAX_ENTROPY="${MAX_ENTROPY:-7.5}"
BATCH_SIZE="${BATCH_SIZE:-25}"
JOB_STATUS_COMPLETE="${JOB_STATUS_COMPLETE:-COMPLETED}"
JOB_STATUS_FAILED="${JOB_STATUS_FAILED:-QUARANTINED}"
TOPIC_IN="${TOPIC_IN:-sanitizer_in}"
TOPIC_CLEAN="${TOPIC_CLEAN:-sanitized_stream}"
YARA_RULES="${YARA_RULES:-/app/rules/rules.yar}"

: "${DB_HOST:=localhost}"
: "${DB_USER:=user}"
: "${DB_PASSWORD:=password}"
: "${DB_NAME:=sanitizer_db}"
: "${KAFKA_BOOTSTRAP:=localhost:9092}"


trap 'rm -f /dev/shm/tmp_*' EXIT
source "libs/db_lib.sh"
source "libs/san_lib.sh"
source "libs/kafka_lib.sh"
# Main loop: consume from Kafka topic
 consume_messages "$INPUT_TOPIC" 10000 1 | while read -r msg; do
   [[ -z "$msg" ]] && continue
   sanitize_message "$msg"
   echo "Received message: $msg"
 done
