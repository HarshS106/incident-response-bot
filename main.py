"""
main.py
-------
CLI and lightweight webhook server for the Incident Response Bot.

Usage:
    # Simulate a compromised account alert (dry run)
    python main.py --simulate compromised_account

    # Simulate brute force alert
    python main.py --simulate brute_force

    # Start webhook listener on port 5000 (receives alerts from Splunk/Sentinel)
    python main.py --serve --port 5000

    # Process a JSON alert file
    python main.py --alert sample_data/sample_alert.json
"""

import sys
import json
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.ir_bot import IRBot, SecurityAlert, AlertSeverity

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Sample Alerts for Demo ────────────────────────────────────────────────────
SAMPLE_ALERTS = {
    "compromised_account": {
        "alert_id":   "ALERT-001",
        "alert_type": "compromised_account",
        "severity":   "CRITICAL",
        "source":     "splunk",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "indicators": {
            "user":       "jdoe@company.com",
            "source_ip":  "41.203.18.75",
            "country":    "Nigeria",
        },
    },
    "brute_force": {
        "alert_id":   "ALERT-002",
        "alert_type": "brute_force",
        "severity":   "HIGH",
        "source":     "aws_security_hub",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "indicators": {
            "source_ip":      "185.220.101.45",
            "target_service": "AWS Console",
            "failed_attempts": 47,
        },
    },
    "crypto_mining": {
        "alert_id":   "ALERT-003",
        "alert_type": "crypto_mining",
        "severity":   "HIGH",
        "source":     "aws_security_hub",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "indicators": {
            "instance_id": "i-0abc12345def67890",
            "region":      "us-east-1",
            "cpu_spike":   "98%",
            "process":     "xmrig",
        },
    },
    "data_exfiltration": {
        "alert_id":   "ALERT-004",
        "alert_type": "data_exfiltration",
        "severity":   "CRITICAL",
        "source":     "splunk",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "indicators": {
            "user":      "svc-etl@company.com",
            "s3_bucket": "company-customer-data",
            "bytes_out": "4.7GB",
            "dest_ip":   "198.51.100.22",
        },
    },
}


def run_simulation(alert_type: str, dry_run: bool = True) -> None:
    sample = SAMPLE_ALERTS.get(alert_type)
    if not sample:
        print(f"Unknown alert type '{alert_type}'. Choose from: {list(SAMPLE_ALERTS)}")
        sys.exit(1)

    alert = SecurityAlert(
        alert_id   = sample["alert_id"],
        alert_type = sample["alert_type"],
        severity   = AlertSeverity(sample["severity"]),
        source     = sample["source"],
        timestamp  = sample["timestamp"],
        indicators = sample["indicators"],
        raw        = sample,
    )

    config = {"slack_channel": "#security-alerts"}
    bot    = IRBot(config=config, dry_run=dry_run)
    result = bot.handle(alert)

    print("\n" + "=" * 60)
    print(f"  INCIDENT RESPONSE BOT — PLAYBOOK COMPLETE")
    print("=" * 60)
    print(f"  Alert ID : {result.alert_id}")
    print(f"  Playbook : {result.playbook}")
    print(f"  Status   : {result.status.value}")
    print(f"  Duration : {result.started_at} → {result.ended_at}")
    print("\n  Timeline:")
    for entry in result.timeline:
        print(f"    {entry}")
    print("\n  Steps:")
    for step in result.steps_run:
        icon = "✅" if step["status"] == "success" else "❌"
        print(f"    {icon} {step['step']}: {step.get('output', step.get('error', ''))}")
    print("=" * 60 + "\n")

    output_path = f"ir_result_{alert_type}.json"
    Path(output_path).write_text(json.dumps(result.to_dict(), indent=2))
    log.info("Playbook result saved → %s", output_path)


def run_from_file(alert_path: str) -> None:
    data  = json.loads(Path(alert_path).read_text())
    alert = SecurityAlert(
        alert_id   = data["alert_id"],
        alert_type = data["alert_type"],
        severity   = AlertSeverity(data["severity"]),
        source     = data.get("source", "unknown"),
        timestamp  = data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        indicators = data.get("indicators", {}),
        raw        = data,
    )
    bot    = IRBot(dry_run=True)
    result = bot.handle(alert)
    print(json.dumps(result.to_dict(), indent=2))


def run_webhook_server(port: int = 5000) -> None:
    """
    Lightweight Flask webhook that receives alerts from Splunk / Sentinel.
    Requires: pip install flask
    """
    try:
        from flask import Flask, request, jsonify
    except ImportError:
        log.error("Flask not installed. Run: pip install flask")
        sys.exit(1)

    app = Flask(__name__)
    bot = IRBot(config={"slack_channel": "#security-alerts"}, dry_run=True)

    @app.route("/webhook/alert", methods=["POST"])
    def receive_alert():
        data = request.get_json(force=True)
        try:
            alert = SecurityAlert(
                alert_id   = data.get("alert_id", f"WH-{datetime.now().strftime('%H%M%S')}"),
                alert_type = data["alert_type"],
                severity   = AlertSeverity(data.get("severity", "HIGH")),
                source     = data.get("source", "webhook"),
                timestamp  = data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                indicators = data.get("indicators", {}),
                raw        = data,
            )
            result = bot.handle(alert)
            return jsonify(result.to_dict()), 200
        except Exception as exc:
            log.error("Failed to process webhook alert: %s", exc)
            return jsonify({"error": str(exc)}), 400

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "bot": "incident-response-bot", "version": "1.0.0"})

    log.info("IR Bot webhook server starting on port %d", port)
    app.run(host="0.0.0.0", port=port)


def main():
    parser = argparse.ArgumentParser(
        description="Automated Incident Response Bot — playbook-driven security automation"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--simulate", metavar="ALERT_TYPE",
                       choices=list(SAMPLE_ALERTS),
                       help=f"Simulate an alert. Choices: {list(SAMPLE_ALERTS)}")
    group.add_argument("--alert",    metavar="FILE",
                       help="Process a JSON alert file")
    group.add_argument("--serve",    action="store_true",
                       help="Start webhook listener")
    parser.add_argument("--port",    type=int, default=5000,
                        help="Webhook server port (default: 5000)")
    parser.add_argument("--live",    action="store_true",
                        help="Disable dry-run and execute actions for real (use with caution)")
    args = parser.parse_args()

    if args.simulate:
        run_simulation(args.simulate, dry_run=not args.live)
    elif args.alert:
        run_from_file(args.alert)
    elif args.serve:
        run_webhook_server(args.port)


if __name__ == "__main__":
    main()
