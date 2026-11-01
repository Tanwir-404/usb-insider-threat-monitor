"""USBGuard adapter. MODE=mock (default, works on macOS) or MODE=real (Linux endpoint)."""
import os, re, subprocess
from datetime import date

MODE = os.environ.get("MODE", "mock")

CLASS_NAMES = {"01": "Audio", "03": "HID", "08": "Mass Storage", "09": "Hub",
               "07": "Printer", "0e": "Video", "e0": "Wireless", "ff": "Vendor-specific"}

# ---------- mock data (in memory) ----------
_MOCK = [
    {"id": "1", "name": "Logitech USB Keyboard", "vidpid": "046d:c31c", "ifaces": ["03"],
     "status": "allowed", "approved": "01 Nov 2026"},
    {"id": "2", "name": "SanDisk Cruzer Blade", "vidpid": "0781:5567", "ifaces": ["08"],
     "status": "pending", "approved": ""},
    {"id": "3", "name": "Unknown keyboard + storage", "vidpid": "16c0:27db", "ifaces": ["03", "08"],
     "status": "blocked", "approved": ""},
    {"id": "4", "name": "USB Optical Mouse", "vidpid": "093a:2510", "ifaces": ["03"],
     "status": "allowed", "approved": "01 Nov 2026"},
]
_MOCK_ALERTS = [
    {"time": "14:35:51", "level": 10, "rule": "File copied to USB drive", "detail": "report_final.pdf (2.4 MB)"},
    {"time": "14:32:08", "level": 12, "rule": "USB device blocked by USBGuard", "detail": "SanDisk Cruzer Blade"},
    {"time": "14:31:40", "level": 14, "rule": "HID device with storage interface", "detail": "Unknown keyboard + storage"},
    {"time": "14:29:12", "level": 5, "rule": "USB device allowed by admin", "detail": "Logitech USB Keyboard"},
]

def _decorate(d):
    d["classes"] = " + ".join(CLASS_NAMES.get(i, i) for i in d["ifaces"])
    d["suspicious"] = "03" in d["ifaces"] and "08" in d["ifaces"]  # keyboard hiding in a storage device
    return d

# ---------- real mode helpers ----------
_LINE = re.compile(r'^(\d+): (\w+) id (\S+) serial "(.*?)" name "(.*?)" hash "(.*?)".*?with-interface (.*?)(?: with-connect-type.*)?$')

def _run(args):
    return subprocess.run(["sudo", "usbguard"] + args, capture_output=True, text=True, timeout=10)

def list_devices():
    if MODE == "mock":
        return [_decorate(dict(d)) for d in _MOCK]
    out = _run(["list-devices"]).stdout.splitlines()
    devices = []
    for line in out:
        m = _LINE.match(line.strip())
        if not m:
            continue
        num, target, vidpid, serial, name, _hash, ifs = m.groups()
        ifs = ifs.strip("{} ")
        ifaces = sorted({i.split(":")[0] for i in ifs.split()})
        status = {"allow": "allowed", "block": "blocked", "reject": "blocked"}.get(target, "pending")
        devices.append(_decorate({"id": num, "name": name or "(unnamed)", "vidpid": vidpid,
                                  "ifaces": ifaces, "status": status, "approved": ""}))
    return devices

def set_status(dev_id, new_status):
    if not dev_id.isdigit():
        return False
    if MODE == "mock":
        for d in _MOCK:
            if d["id"] == dev_id:
                d["status"] = new_status
                d["approved"] = date.today().strftime("%d %b %Y") if new_status == "allowed" else ""
                return True
        return False
    cmd = ["allow-device", "-p", dev_id] if new_status == "allowed" else ["block-device", dev_id]
    return _run(cmd).returncode == 0

def trusted_devices():
    return [d for d in list_devices() if d["status"] == "allowed"]

# ---------- alerts ----------
def get_alerts(limit=20):
    if MODE == "mock":
        return _MOCK_ALERTS
    import requests, urllib3
    urllib3.disable_warnings()
    host = os.environ.get("WAZUH_INDEXER", "https://localhost:9200")
    auth = (os.environ.get("WAZUH_USER", "admin"), os.environ.get("WAZUH_PASS", ""))
    body = {"size": limit, "sort": [{"timestamp": "desc"}],
            "query": {"bool": {"should": [{"match": {"rule.groups": "usb"}},
                                          {"match": {"rule.groups": "usbguard"}}],
                               "minimum_should_match": 1}}}
    try:
        r = requests.post(f"{host}/wazuh-alerts-*/_search", json=body, auth=auth, verify=False, timeout=8)
        hits = r.json()["hits"]["hits"]
    except Exception:
        return []
    return [{"time": h["_source"]["timestamp"][11:19], "level": h["_source"]["rule"]["level"],
             "rule": h["_source"]["rule"]["description"],
             "detail": h["_source"].get("full_log", "")[:80]} for h in hits]
