#!/bin/bash

set -euo pipefail
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../libs/kafka_lib.sh
source "${SCRIPT_DIR}/../libs/kafka_lib.sh"

trap 'rm -f /dev/shm/tmp_*' EXIT

usage() {
  echo "Usage:"
  echo "  $0 '<base64_payload>'"
  echo "  echo '<base64_payload>' | $0"
}

require_cmd jq
require_cmd kcat
require_cmd openssl
require_cmd python3

if ! payload="$(read_payload "${1:-}")"; then
  usage >&2
  exit 1
fi

if [[ -z "$payload" ]]; then
  echo "Payload is empty" >&2
  exit 1
fi

if ! validate_base64 "$payload"; then
  echo "Invalid base64 payload" >&2
  exit 1
fi

json_message="$(build_message \
  "$payload" \
  "$INPUT_TOPIC" \
  "$MESSAGE_ORIGIN" \
  "$MESSAGE_SOURCE" \
  "$MESSAGE_TYPE")"

publish_message "$INPUT_TOPIC" "$json_message"

echo "Published message to topic: $INPUT_TOPIC"

# Consume the last message just published from the topic
echo "Consuming last message from topic: $INPUT_TOPIC"
sleep 1
consumed_message="$(consume_messages "$INPUT_TOPIC" 10000 1 || true)"

if [[ -z "${consumed_message:-}" ]]; then
  echo "No message consumed from topic: $INPUT_TOPIC" >&2
  exit 1
fi

echo "Consumed raw message:"
echo "$consumed_message"

echo "Pretty-printed message:"
pretty_print_message "$consumed_message"


