"""
Audit logger for IAM Framework.

Every access decision (allow or deny) gets written to:
  1. A local structured log file (always)
  2. CloudWatch Logs (if configured)
  3. S3 (batched, for Athena querying)

The log schema is deliberately flat so Athena can query it without
needing a complex SerDe configuration.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import boto3

logger = logging.getLogger(__name__)

LOG_DIR = Path(os.environ.get("AUDIT_LOG_DIR", "./audit_logs"))
CW_LOG_GROUP = os.environ.get("CW_LOG_GROUP", "/iam-framework/access-decisions")
S3_AUDIT_BUCKET = os.environ.get("S3_AUDIT_BUCKET", "")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


class AuditLogger:
    """
    Records access decisions in a structured, queryable format.

    The same instance is meant to be reused across requests — it
    maintains a CloudWatch Logs sequence token internally.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._cw_sequence_token: Optional[str] = None
        self._cw_client = None
        self._s3_client = None
        self._pending_s3_records: list[dict] = []

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._log_path = LOG_DIR / f"{tenant_id}_access.log"

    def log_decision(
        self,
        principal: str,
        action: str,
        resource: str,
        decision: str,
        reason: str,
        session_tags: dict = None,
        source_ip: str = "",
        request_id: str = "",
    ) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": self.tenant_id,
            "principal": principal,
            "action": action,
            "resource": resource,
            "decision": decision.upper(),
            "reason": reason,
            "source_ip": source_ip,
            "request_id": request_id,
            "session_tags": session_tags or {},
        }

        self._write_local(record)
        self._write_cloudwatch(record)

        if decision.upper() == "DENY":
            # Denied requests get flagged for immediate S3 flush
            self._pending_s3_records.append(record)
            if len(self._pending_s3_records) >= 10:
                self.flush_to_s3()

        logger.info(
            "[%s] %s %s → %s (%s) [%s]",
            self.tenant_id, principal, action, decision.upper(), reason, source_ip or "internal"
        )

    def _write_local(self, record: dict) -> None:
        try:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as e:
            logger.error("Failed to write audit log: %s", e)

    def _write_cloudwatch(self, record: dict) -> None:
        if not CW_LOG_GROUP:
            return
        try:
            if self._cw_client is None:
                self._cw_client = boto3.client("logs", region_name=AWS_REGION)
                self._ensure_log_stream()

            kwargs = {
                "logGroupName": CW_LOG_GROUP,
                "logStreamName": self.tenant_id,
                "logEvents": [{
                    "timestamp": int(time.time() * 1000),
                    "message": json.dumps(record),
                }],
            }
            if self._cw_sequence_token:
                kwargs["sequenceToken"] = self._cw_sequence_token

            resp = self._cw_client.put_log_events(**kwargs)
            self._cw_sequence_token = resp.get("nextSequenceToken")
        except Exception as e:
            logger.debug("CloudWatch write failed (non-fatal): %s", e)

    def _ensure_log_stream(self) -> None:
        try:
            self._cw_client.create_log_stream(
                logGroupName=CW_LOG_GROUP,
                logStreamName=self.tenant_id,
            )
        except self._cw_client.exceptions.ResourceAlreadyExistsException:
            pass

    def flush_to_s3(self) -> None:
        if not S3_AUDIT_BUCKET or not self._pending_s3_records:
            return
        try:
            if self._s3_client is None:
                self._s3_client = boto3.client("s3", region_name=AWS_REGION)

            key = (
                f"audit-logs/{self.tenant_id}/"
                f"{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/"
                f"{int(time.time())}.jsonl"
            )
            body = "\n".join(json.dumps(r) for r in self._pending_s3_records)
            self._s3_client.put_object(
                Bucket=S3_AUDIT_BUCKET,
                Key=key,
                Body=body.encode(),
                ContentType="application/x-ndjson",
            )
            logger.info("Flushed %d audit records to s3://%s/%s", len(self._pending_s3_records), S3_AUDIT_BUCKET, key)
            self._pending_s3_records.clear()
        except Exception as e:
            logger.error("S3 audit flush failed: %s", e)
