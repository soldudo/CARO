#!/usr/bin/env python3
"""
CARO Notification Sender
Reads notify_config.json and sends via ntfy.sh.
"""
import json
import sys
import urllib.request
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / 'config' / 'notify_config.json'

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

def send_notification(title: str, body: str):
    cfg = load_config()
    send_ntfy(title, body, cfg['ntfy'])

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: send_notification.py <title> <body>")
        sys.exit(1)
    send_notification(sys.argv[1], sys.argv[2])
