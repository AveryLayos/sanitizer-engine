#!/bin/bash
# This script continuously reads from topic sanitizer_in, processes the messages, and then publish the sanitized results to topic sanitizer_out.
set -euo pipefail
set -o pipefail 




# Source sanitization library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/bin/san_lib.sh"
source "$SCRIPT_DIR/bin/kafka_lib.sh"
source "$SCRIPT_DIR/bin/db_lib.sh"
source "$SCRIPT_DIR/bin/file_lib.sh"

# Configuration
QUARANTINE_DIR="./quarantine"
OUTPUT_DIR="./sanitized_output"
