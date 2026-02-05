#!/usr/bin/env python
# encoding: utf-8

"""
/bin/dragos_email_alert.py

Dragos OT Security for Splunk App
Email Alert Action

========================================================================
FIELDS— ALERT ACTION PAYLOAD
========================================================================

Payload structure:

payload
├── configuration
│   ├── to                    (string, comma-separated)
│   ├── cc                    (string, comma-separated, optional)
│   ├── subject               (string)
│   ├── message               (string)
│   ├── priority              (string: high | normal | low)
│   ├── include_results       (string: "1" | "0")
│   ├── include_link          (string: "1" | "0")
│   ├── smtp_server           (string)
│   ├── smtp_port             (string/int)
│   ├── smtp_use_tls          (string: "1" | "0")
│   ├── smtp_user             (string, optional)
│   ├── smtp_password         (string, optional)
│   ├── from_address          (string)
│
├── result                    (dict, OPTIONAL)
│   ├── *                     (ALL fields passed through verbatim)
│   └── _*                    (ignored — Splunk internal fields)
│
├── results_link              (string, OPTIONAL)
│
========================================================================
DESIGN PRINCIPLES
========================================================================
- No field normalization
- No schema assumptions
- No enrichment
- Raw key/value passthrough
- HTML rendering is presentation-only
- Splunk owns payload structure
"""

import sys
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))


# ----------------------------------------------------------------------
# Email sender
# ----------------------------------------------------------------------
def send_email(config, payload):
    """
    Send email notification using Splunk-provided payload
    """

    # ------------------------------------------------------------------
    # Alert configuration (alert_actions.conf)
    # ------------------------------------------------------------------
    to_addresses = config.get("to", "").split(",")
    cc_addresses = config.get("cc", "").split(",") if config.get("cc") else []

    subject = config.get("subject", "Dragos Alert")
    message_body = config.get("message", "")
    priority = config.get("priority", "normal")

    include_results = config.get("include_results", "1") == "1"
    include_link = config.get("include_link", "1") == "1"

    # ------------------------------------------------------------------
    # SMTP configuration (Splunk global email settings)
    # ------------------------------------------------------------------
    smtp_server = config.get("smtp_server", "localhost")
    smtp_port = int(config.get("smtp_port", 25))
    smtp_use_tls = config.get("smtp_use_tls", "0") == "1"

    smtp_user = config.get("smtp_user", "")
    smtp_password = config.get("smtp_password", "")
    from_address = config.get("from_address", "splunk@localhost")

    # ------------------------------------------------------------------
    # Build email
    # ------------------------------------------------------------------
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_address
    msg["To"] = ", ".join(to_addresses)

    if cc_addresses:
        msg["Cc"] = ", ".join(cc_addresses)

    # Priority headers
    if priority == "high":
        msg["X-Priority"] = "1"
        msg["Importance"] = "high"
    elif priority == "low":
        msg["X-Priority"] = "5"
        msg["Importance"] = "low"

    # ------------------------------------------------------------------
    # HTML body
    # ------------------------------------------------------------------
    html_body = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .header {{ background-color: #2c3e50; color: white; padding: 15px; }}
            .body {{ padding: 15px; background-color: #f5f5f5; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #34495e; color: white; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2>Dragos OT Security Alert</h2>
        </div>
        <div class="body">
            <p>{message_body.replace(chr(10), "<br>")}</p>
    """

    # ------------------------------------------------------------------
    # Include raw result fields (verbatim passthrough)
    # ------------------------------------------------------------------
    if include_results and payload.get("result"):
        html_body += "<h3>Alert Details</h3><table>"
        for key, value in payload["result"].items():
            if not key.startswith("_"):
                html_body += f"<tr><th>{key}</th><td>{value}</td></tr>"
        html_body += "</table>"

    # ------------------------------------------------------------------
    # Include Splunk results link
    # ------------------------------------------------------------------
    if include_link and payload.get("results_link"):
        html_body += f"""
        <p>
            <a href="{payload['results_link']}">
                View alert results in Splunk
            </a>
        </p>
        """

    html_body += """
        </div>
    </body>
    </html>
    """

    # Attach bodies
    msg.attach(MIMEText(message_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    # ------------------------------------------------------------------
    # Send email
    # ------------------------------------------------------------------
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        if smtp_use_tls:
            server.starttls()

        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)

        recipients = to_addresses + cc_addresses
        server.sendmail(from_address, recipients, msg.as_string())
        server.quit()

        return True, "Email sent successfully"

    except Exception as e:
        return False, str(e)


# ----------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------
def main():

    if len(sys.argv) < 2:
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)

    payload_file = sys.argv[1]

    try:
        with open(payload_file, "r") as fh:
            payload = json.load(fh)
    except Exception as e:
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)

    config = payload.get("configuration", {})

    success, message = send_email(config, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)
    else:
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
