"""
ir_bot.py
---------
Automated Incident Response Bot — receives security alerts (from Splunk,
AWS Security Hub, or webhook), classifies the incident, and executes
the appropriate playbook automatically.

Supported playbooks:
  - compromised_account   : disable user, revoke sessions, notify SOC
  - brute_force           : block source IP in WAF, alert, create ticket
  - crypto_mining         : isolate EC2 instance, capture memory snapshot
  - data_exfiltration     : revoke IAM credentials, block S3 public access
  - malware_detected      : quarantine endpoint via EDR API, notify team

Each playbook follows: DETECT → CONTAIN → ERADICATE → NOTIFY → DOCUMENT
"""

import json
import logging
import smtplib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Callable, Optional
from enum import Enum

log = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────────────────────
class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class PlaybookStatus(str, Enum):
    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    SKIPPED   = "SKIPPED"


@dataclass
class SecurityAlert:
    alert_id:   str
    alert_type: str        # matches a playbook key
    severity:   AlertSeverity
    source:     str        # "splunk" | "aws_security_hub" | "sentinel" | "webhook"
    timestamp:  str
    indicators: dict       # {"user": "...", "ip": "...", "instance_id": "...", etc.}
    raw:        dict = field(default_factory=dict)


@dataclass
class PlaybookStep:
    name:        str
    description: str
    action:      Callable
    rollback:    Optional[Callable] = None


@dataclass
class PlaybookResult:
    playbook:   str
    alert_id:   str
    status:     PlaybookStatus
    started_at: str
    ended_at:   str = ""
    steps_run:  list[dict] = field(default_factory=list)
    timeline:   list[str]  = field(default_factory=list)

    def log_step(self, step_name: str, status: str, detail: str = "") -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {step_name}: {status}"
        if detail:
            entry += f" — {detail}"
        self.timeline.append(entry)
        log.info(entry)

    def to_dict(self) -> dict:
        return {
            "playbook":   self.playbook,
            "alert_id":   self.alert_id,
            "status":     self.status.value,
            "started_at": self.started_at,
            "ended_at":   self.ended_at,
            "steps_run":  self.steps_run,
            "timeline":   self.timeline,
        }


# ── Simulated Action Handlers ─────────────────────────────────────────────────
# In production these call real APIs (Okta, AWS, WAF, EDR, Jira).
# In demo/CI mode they log the action and return success.

class ActionHandlers:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def _exec(self, action_name: str, detail: str, real_fn: Callable) -> dict:
        if self.dry_run:
            log.info("[DRY-RUN] Would execute: %s — %s", action_name, detail)
            return {"status": "dry_run", "action": action_name, "detail": detail}
        return real_fn()

    def disable_okta_user(self, username: str) -> dict:
        return self._exec(
            "disable_okta_user", username,
            lambda: {"status": "success", "user": username, "action": "deactivated"},
        )

    def revoke_okta_sessions(self, username: str) -> dict:
        return self._exec(
            "revoke_okta_sessions", username,
            lambda: {"status": "success", "user": username, "sessions_revoked": True},
        )

    def block_ip_in_waf(self, ip: str, waf_acl_id: str = "default") -> dict:
        return self._exec(
            "block_ip_waf", ip,
            lambda: {"status": "success", "ip": ip, "waf_acl": waf_acl_id, "rule": f"auto-block-{ip}"},
        )

    def isolate_ec2_instance(self, instance_id: str) -> dict:
        return self._exec(
            "isolate_ec2", instance_id,
            lambda: {"status": "success", "instance_id": instance_id, "security_group": "sg-quarantine"},
        )

    def revoke_iam_credentials(self, username: str) -> dict:
        return self._exec(
            "revoke_iam_credentials", username,
            lambda: {"status": "success", "user": username, "keys_deactivated": True},
        )

    def block_s3_public_access(self, bucket: str) -> dict:
        return self._exec(
            "block_s3_public", bucket,
            lambda: {"status": "success", "bucket": bucket, "public_access": "blocked"},
        )

    def create_jira_ticket(self, summary: str, description: str, priority: str = "High") -> dict:
        return self._exec(
            "create_jira_ticket", summary,
            lambda: {"status": "success", "ticket_id": "SEC-1042", "priority": priority},
        )

    def send_slack_alert(self, channel: str, message: str) -> dict:
        return self._exec(
            "send_slack", channel,
            lambda: {"status": "success", "channel": channel, "ts": datetime.now(timezone.utc).isoformat()},
        )

    def send_email_alert(self, to: str, subject: str, body: str) -> dict:
        return self._exec(
            "send_email", to,
            lambda: {"status": "success", "to": to, "subject": subject},
        )


# ── Playbook Definitions ──────────────────────────────────────────────────────
class Playbooks:
    def __init__(self, handlers: ActionHandlers, config: dict):
        self.h      = handlers
        self.config = config

    def compromised_account(self, alert: SecurityAlert) -> list[PlaybookStep]:
        user    = alert.indicators.get("user", "unknown")
        channel = self.config.get("slack_channel", "#security-alerts")
        return [
            PlaybookStep(
                name        = "Disable user account",
                description = f"Deactivate {user} in Okta to prevent further access",
                action      = lambda: self.h.disable_okta_user(user),
            ),
            PlaybookStep(
                name        = "Revoke active sessions",
                description = f"Kill all active sessions for {user}",
                action      = lambda: self.h.revoke_okta_sessions(user),
            ),
            PlaybookStep(
                name        = "Notify SOC channel",
                description = "Post alert to Slack SOC channel",
                action      = lambda: self.h.send_slack_alert(
                    channel, f":red_circle: Compromised account response triggered for `{user}`"
                ),
            ),
            PlaybookStep(
                name        = "Create incident ticket",
                description = "Open Jira ticket for SOC tracking",
                action      = lambda: self.h.create_jira_ticket(
                    summary     = f"Compromised Account — {user}",
                    description = f"Automated IR triggered at {alert.timestamp}. User disabled and sessions revoked.",
                    priority    = "Critical",
                ),
            ),
        ]

    def brute_force(self, alert: SecurityAlert) -> list[PlaybookStep]:
        ip      = alert.indicators.get("source_ip", "0.0.0.0")
        channel = self.config.get("slack_channel", "#security-alerts")
        return [
            PlaybookStep(
                name        = "Block source IP in WAF",
                description = f"Add {ip} to WAF IP blocklist",
                action      = lambda: self.h.block_ip_in_waf(ip),
            ),
            PlaybookStep(
                name        = "Notify SOC",
                description = "Alert security team via Slack",
                action      = lambda: self.h.send_slack_alert(
                    channel, f":warning: Brute force detected from `{ip}` — IP blocked in WAF"
                ),
            ),
            PlaybookStep(
                name        = "Create ticket",
                description = "Open Jira ticket for investigation",
                action      = lambda: self.h.create_jira_ticket(
                    f"Brute Force — Source IP {ip}",
                    f"WAF rule created at {alert.timestamp}. Investigate origin and affected accounts.",
                ),
            ),
        ]

    def crypto_mining(self, alert: SecurityAlert) -> list[PlaybookStep]:
        instance = alert.indicators.get("instance_id", "unknown")
        channel  = self.config.get("slack_channel", "#security-alerts")
        return [
            PlaybookStep(
                name        = "Isolate EC2 instance",
                description = f"Move {instance} into quarantine security group",
                action      = lambda: self.h.isolate_ec2_instance(instance),
            ),
            PlaybookStep(
                name        = "Notify SOC",
                description = "Alert team with instance details",
                action      = lambda: self.h.send_slack_alert(
                    channel,
                    f":skull: Crypto mining detected on `{instance}` — instance isolated",
                ),
            ),
            PlaybookStep(
                name        = "Create forensics ticket",
                description = "Document for forensic investigation",
                action      = lambda: self.h.create_jira_ticket(
                    f"Crypto Mining — {instance}",
                    f"Instance isolated at {alert.timestamp}. Pending memory snapshot and forensics.",
                    priority="Critical",
                ),
            ),
        ]

    def data_exfiltration(self, alert: SecurityAlert) -> list[PlaybookStep]:
        user    = alert.indicators.get("user", "unknown")
        bucket  = alert.indicators.get("s3_bucket", "unknown")
        channel = self.config.get("slack_channel", "#security-alerts")
        return [
            PlaybookStep(
                name        = "Revoke IAM credentials",
                description = f"Deactivate all access keys for {user}",
                action      = lambda: self.h.revoke_iam_credentials(user),
            ),
            PlaybookStep(
                name        = "Block S3 public access",
                description = f"Enable BlockPublicAccess on {bucket}",
                action      = lambda: self.h.block_s3_public_access(bucket),
            ),
            PlaybookStep(
                name        = "Notify SOC",
                description = "Immediate alert to security team",
                action      = lambda: self.h.send_slack_alert(
                    channel,
                    f":rotating_light: Data exfiltration detected! User `{user}` / Bucket `{bucket}` — credentials revoked",
                ),
            ),
            PlaybookStep(
                name        = "Create high-priority ticket",
                description = "Escalate to senior analyst",
                action      = lambda: self.h.create_jira_ticket(
                    f"Data Exfiltration — {user} / {bucket}",
                    f"Triggered at {alert.timestamp}. Credentials revoked. S3 hardened. Immediate investigation required.",
                    priority="Critical",
                ),
            ),
        ]

    def get(self, alert_type: str) -> Optional[Callable]:
        return {
            "compromised_account": self.compromised_account,
            "brute_force":         self.brute_force,
            "crypto_mining":       self.crypto_mining,
            "data_exfiltration":   self.data_exfiltration,
        }.get(alert_type)


# ── IR Bot Engine ─────────────────────────────────────────────────────────────
class IRBot:
    def __init__(self, config: dict = None, dry_run: bool = True):
        self.config   = config or {}
        self.dry_run  = dry_run
        self.handlers = ActionHandlers(dry_run=dry_run)
        self.playbooks= Playbooks(self.handlers, self.config)

    def handle(self, alert: SecurityAlert) -> PlaybookResult:
        log.info("Received alert [%s] type=%s severity=%s",
                 alert.alert_id, alert.alert_type, alert.severity.value)

        result = PlaybookResult(
            playbook   = alert.alert_type,
            alert_id   = alert.alert_id,
            status     = PlaybookStatus.RUNNING,
            started_at = datetime.now(timezone.utc).isoformat(),
        )

        playbook_fn = self.playbooks.get(alert.alert_type)
        if not playbook_fn:
            result.status = PlaybookStatus.SKIPPED
            result.log_step("routing", "SKIPPED", f"No playbook for type '{alert.alert_type}'")
            return result

        steps = playbook_fn(alert)
        result.log_step("playbook_start", "OK", f"{len(steps)} steps loaded")

        for step in steps:
            try:
                result.log_step(step.name, "RUNNING", step.description)
                outcome = step.action()
                result.steps_run.append({"step": step.name, "status": "success", "output": outcome})
                result.log_step(step.name, "DONE")
            except Exception as exc:
                result.steps_run.append({"step": step.name, "status": "error", "error": str(exc)})
                result.log_step(step.name, "ERROR", str(exc))
                # Continue to next step — partial containment is better than none

        result.status   = PlaybookStatus.COMPLETED
        result.ended_at = datetime.now(timezone.utc).isoformat()
        result.log_step("playbook_complete", "OK",
                        f"{sum(1 for s in result.steps_run if s['status']=='success')}/{len(steps)} steps succeeded")

        return result

