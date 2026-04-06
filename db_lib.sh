#!/bin/bash


: "${DB_USE_DOCKER_COMPOSE:=false}"
: "${DB_SERVICE_NAME:=db}"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-user}"
DB_PASSWORD="${DB_PASSWORD:-password}"

DB_NAME="${DB_NAME:-sanitizer_db}"

declare -r STATUS_PENDING="PENDING"
declare -r STATUS_QUEUED="QUEUED"


declare -r STATUS_SANITIZING="SANITIZING"
declare -r STATUS_SANITIZED="SANITIZED"
declare -r STATUS_FAILED_SANITIZATION="FAILED_SANITIZATION"

declare -r STATUS_AI_PROCESSING_PENDING="AI_PROCESSING_PENDING"

declare -r STATUS_AI_PROCESSING="AI_PROCESSING"
declare -r STATUS_AI_PROCESSED="AI_PROCESSED"


declare -r STATUS_IN_PROGRESS="IN_PROGRESS"
declare -r STATUS_RETRYING="RETRYING"


declare -r STATUS_COMPLETED="COMPLETED"
declare -r STATUS_COMPLETED_WITH_WARNINGS="COMPLETED_WITH_WARNINGS"
declare -r STATUS_ERROR="ERROR"
declare -r STATUS_CANCELLED="CANCELLED"


current_status=$STATUS_PENDING

run_mysql() {
  local sql="$1"
  MYSQL_PWD="$DB_PASSWORD" mysql --protocol=TCP \
    -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -D "$DB_NAME" \
    --batch --raw --skip-column-names \
    -e "$sql"
}

insert_job_request() {
  local b64_data="$1"
  run_mysql "
    INSERT INTO job_request (
      file_name,
      file_content,
      file_content_content_type,
      file_type,
      status,
      request_type,
      priority,
      user_id
    ) VALUES (
      '$FILE_NAME',
      FROM_BASE64('$b64_data'),
      'text/csv',
      'LOG',
      'PENDING',
      'SANITIZE',
      '$PRIORITY',
      '$USER_ID'
    );
  "
}

read_latest_job_request() {
  run_mysql  "
      SELECT
        id,
        COALESCE(file_name, ''),
        COALESCE(file_content_content_type, ''),
        REPLACE(TO_BASE64(file_content), '\n', '')
      FROM job_request
      ORDER BY id DESC
      LIMIT 1;
    "
}

delete_job_request_by_id() {
  local job_id="$1"
  run_mysql "
    DELETE FROM job_request
    WHERE id = ${job_id}
    LIMIT 1;
  "
}

update_job_request_status() {
  local job_id="$1"
  local status="$2"
  run_mysql "
    UPDATE job_request
    SET status = '$status'
    WHERE id = ${job_id};
  "
}

insert_execution_log() {
    local job_id="$1"
    local user_id="$2"
    local status="$3"
    local log_msg="$4"

    # We use run_mysql so it inherits the TCP protocol and credentials
    run_mysql "INSERT INTO job_execution_report 
      (start_time, execution_node, execution_log, status, job_request_id, user_id)
      VALUES (NOW(6), '$(hostname)', '$log_msg', '$status', '$job_id', '$user_id');"
}

read_latest_pending_job_request() {
    run_mysql "SELECT id, file_name, file_content_content_type, 
      REPLACE(TO_BASE64(file_content), '\n', '') 
      FROM job_request 
      WHERE status = '$STATUS_PENDING' 
      ORDER BY id DESC LIMIT 1;"
}


