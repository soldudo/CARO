#!/usr/bin/env python3
"""
CARO Notification Sender
Reads notify_config.json and sends via ntfy.sh or SMTP.
"""
import json
import smtplib
import sys
import urllib.request
from email.mime.text import MIMEText
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / 'notify_config.json'

def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

def send_ntfy(title: str, body: str, cfg: dict):
    url = f"{cfg['url'].rstrip('/')}/{cfg['topic']}"
    req = urllib.request.Request(url, data=body.encode('utf-8'), method='POST')
    req.add_header('Title', title)
    req.add_header('Priority', 'default')
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(f"ntfy sent [{resp.status}]: {title}")

def send_smtp(title: str, body: str, cfg: dict):
    msg = MIMEText(body)
    msg['Subject'] = title
    msg['From']    = cfg['sender']
    msg['To']      = cfg['recipient']
    with smtplib.SMTP(cfg['server'], cfg['port'], timeout=10) as s:
        s.starttls()
        s.login(cfg['sender'], cfg['password'])
        s.sendmail(cfg['sender'], cfg['recipient'], msg.as_string())
    print(f"SMTP sent: {title}")

def send_notification(title: str, body: str):
    cfg = load_config()
    method = cfg.get('method', 'ntfy')
    if method == 'ntfy':
        send_ntfy(title, body, cfg['ntfy'])
    elif method == 'smtp':
        send_smtp(title, body, cfg['smtp'])
    else:
        raise ValueError(f"Unknown notification method: {method}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: send_email.py <title> <body>")
        sys.exit(1)
    send_notification(sys.argv[1], sys.argv[2])
