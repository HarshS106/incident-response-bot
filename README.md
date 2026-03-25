# Automated Incident Response Bot

**Playbook-driven security automation bot** that receives alerts from Splunk, AWS Security Hub, or any webhook, classifies the incident type, and automatically executes containment and notification steps.

---

## What It Does

Receives a security alert → selects the right playbook → runs containment steps automatically:

| Alert Type | Playbook Steps |
|---|---|
| `compromised_account` | Disable Okta user → revoke sessions → Slack alert → Jira ticket |
| `brute_force` | Block IP in WAF → Slack alert → Jira ticket |
| `crypto_mining` | Isolate EC2 instance → Slack alert → forensics ticket |
| `data_exfiltration` | Revoke IAM credentials → block S3 public access → critical escalation |

---

## Quick Start

```bash
git clone https://github.com/YOUR-USERNAME/incident-response-bot
cd incident-response-bot
pip install -r requirements.txt

# Simulate a compromised account response (dry-run — no real API calls)
python main.py --simulate compromised_account

# Simulate brute force response
python main.py --simulate brute_force

# Simulate crypto mining containment
python main.py --simulate crypto_mining

# Start webhook listener (receives alerts from Splunk/Sentinel)
pip install flask
python main.py --serve --port 5000

# Process an alert JSON file
python main.py --alert sample_data/sample_alert.json
```

---

## Sample Output

```
================================================================
  INCIDENT RESPONSE BOT — PLAYBOOK COMPLETE
================================================================
  Alert ID : ALERT-001
  Playbook : compromised_account
  Status   : COMPLETED

  Timeline:
    [14:22:01] playbook_start: OK — 4 steps loaded
    [14:22:01] Disable user account: RUNNING — Deactivate jdoe@company.com in Okta
    [14:22:01] Disable user account: DONE
    [14:22:01] Revoke active sessions: DONE
    [14:22:01] Notify SOC channel: DONE
    [14:22:01] Create incident ticket: DONE
    [14:22:01] playbook_complete: OK — 4/4 steps succeeded

  Steps:
    ✅ Disable user account: {'status': 'dry_run', 'action': 'disable_okta_user'}
    ✅ Revoke active sessions: {'status': 'dry_run', ...}
    ✅ Notify SOC channel: {'status': 'dry_run', ...}
    ✅ Create incident ticket: {'status': 'dry_run', 'ticket_id': 'SEC-1042'}
```

---

## Webhook Integration (Splunk / Sentinel)

Start the webhook server:
```bash
python main.py --serve --port 5000
```

Send an alert from Splunk alert action or any HTTP client:
```bash
curl -X POST http://localhost:5000/webhook/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "SPL-001",
    "alert_type": "brute_force",
    "severity": "HIGH",
    "source": "splunk",
    "indicators": {"source_ip": "185.220.101.45"}
  }'
```

---

## Project Structure

```
incident-response-bot/
├── main.py                        # CLI + Flask webhook server
├── src/
│   └── ir_bot.py                  # Playbooks, action handlers, IRBot engine
├── sample_data/
│   └── sample_alert.json          # Example alert JSON
├── tests/
│   └── test_ir_bot.py
├── requirements.txt
└── README.md
```

---

## Skills Demonstrated

`Python` · `Incident Response` · `Security Automation` · `Okta API` · `AWS IAM` · `WAF` · `Jira` · `Slack API` · `Flask` · `Playbook Design` · `SOC Operations`

---

## Author

**Harshith Shiva** — Cybersecurity Engineer  
[LinkedIn](https://linkedin.com/in/YOUR-LINKEDIN) · [Portfolio](https://YOUR-PORTFOLIO-URL)
