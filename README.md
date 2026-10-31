# my-first-project-kaliguard-
my first project is a firewall tool
nano kaliguard.py
#!/usr/bin/env python3
"""KaliGuard: a beginner-friendly nftables manager."""

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

TABLE = "kaliguard"
CHAIN = "input"
ROOT = Path.home() / ".local" / "share" / "kaliguard"
STATE_FILE = ROOT / "state.json"
PRESETS = Path.home() / "kaliguard" / "presets"
LOG_FILE = ROOT / "audit.log"

ROOT.mkdir(parents=True, exist_ok=True)
PRESETS.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

def run_nft(args, check=True):
    """Run nftables through sudo without invoking a shell."""
    result = subprocess.run(
        ["sudo", "nft", *args],
        text=True,
        capture_output=True,
        timeout=15,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or "nft command failed")
    return result

def load_state():
    if not STATE_FILE.exists():
        return {"blocked_ips": [], "ports": []}
    data = json.loads(STATE_FILE.read_text())
    if not isinstance(data.get("blocked_ips"), list):
        raise ValueError("Invalid blocked_ips state")
    if not isinstance(data.get("ports"), list):
        raise ValueError("Invalid ports state")
    return data

def save_state(state):
    temp = STATE_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2))
    temp.replace(STATE_FILE)

def ensure_firewall():
    """Create only KaliGuard's table and an accept-policy input chain."""
    result = run_nft(["list", "table", "inet", TABLE], check=False)
    if result.returncode == 0:
        return

    # Refuse to overwrite an existing table if inspection failed for
    # a reason other than the table not existing.
    tables = run_nft(["list", "tables"], check=False)
    if tables.returncode:
        raise RuntimeError(tables.stderr.strip())

    if re.search(r"\btable inet " + TABLE + r"\b", tables.stdout):
        raise RuntimeError("Could not inspect existing KaliGuard table")

    script = (
        f"add table inet {TABLE}\n"
        f"add chain inet {TABLE} {CHAIN} "
        "{ type filter hook input priority 10; policy accept; }\n"
    )
    result = subprocess.run(
        ["sudo", "nft", "-f", "-"],
        input=script, text=True, capture_output=True, timeout=15,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip())

def apply_state(state):
    """Replace only KaliGuard's rules in a single nftables transaction."""
    lines = [f"flush chain inet {TABLE} {CHAIN}"]

    for address in state["blocked_ips"]:
        ip = str(ipaddress.IPv4Address(address))
        lines.append(
            f'add rule inet {TABLE} {CHAIN} '
            f'ip saddr {ip} counter log prefix "KaliGuard blocked: " drop'
        )

    for item in state["ports"]:
        proto = item["protocol"]
        port = int(item["port"])
        if proto not in ("tcp", "udp") or not 1 <= port <= 65535:
            raise ValueError("Invalid saved port rule")
        lines.append(
            f"add rule inet {TABLE} {CHAIN} "
            f"{proto} dport {port} counter accept"
        )

    result = subprocess.run(
        ["sudo", "nft", "-f", "-"],
        input="\n".join(lines) + "\n",
        text=True, capture_output=True, timeout=15,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip())

def audit(message):
    logging.info("%s", message)
    print(message)

def add_block():
    state = load_state()
    raw = input("IPv4 address to block: ").strip()
    address = str(ipaddress.IPv4Address(raw))
    if address in state["blocked_ips"]:
        print("That address is already blocked.")
        return
    if not input(f"Block incoming traffic from {address}? [y/N] ").lower() == "y":
        return
    state["blocked_ips"].append(address)
    apply_state(state)
    save_state(state)
    audit(f"Blocked IPv4 address {address}")

def remove_block():
    state = load_state()
    print("Blocked addresses:", state["blocked_ips"] or "(none)")
    raw = input("IPv4 address to unblock: ").strip()
    address = str(ipaddress.IPv4Address(raw))
    if address not in state["blocked_ips"]:
        print("Address not found.")
        return
    state["blocked_ips"].remove(address)
    apply_state(state)
    save_state(state)
    audit(f"Removed block for {address}")

def add_port_rule():
    state = load_state()
    proto = input("Protocol (tcp/udp): ").strip().lower()
    if proto not in ("tcp", "udp"):
        print("Choose tcp or udp.")
        return
    port = int(input("Destination port (1-65535): ").strip())
    if not 1 <= port <= 65535:
        print("Port out of range.")
        return
    item = {"protocol": proto, "port": port}
    if item in state["ports"]:
        print("Rule already exists.")
        return
    print("This adds an explicit ACCEPT rule in KaliGuard's input chain.")
    print("It does not open a service or override drops in other chains.")
    if input("Continue? [y/N] ").lower() != "y":
        return
    state["ports"].append(item)
    apply_state(state)
    save_state(state)
    audit(f"Added {proto} destination-port accept rule for {port}")

def list_rules():
    state = load_state()
    print("\nBlocked IPv4 addresses:")
    for address in state["blocked_ips"]:
        print(" -", address)
    print("\nExplicit port accept rules:")
    for item in state["ports"]:
        print(f" - {item['protocol']} port {item['port']}")
    print("\nLive KaliGuard nftables rules:")
    result = run_nft(["-a", "list", "table", "inet", TABLE], check=False)
    print(result.stdout or result.stderr or "(no rules)")

def monitor():
    print("\nListening sockets:")
    subprocess.run(["ss", "-lntup"], check=False)
    print("\nActive TCP connections:")
    subprocess.run(["ss", "-tn"], check=False)

def show_logs():
    if LOG_FILE.exists():
        print(LOG_FILE.read_text()[-12000:])
    else:
        print("No audit events recorded yet.")
    print("\nKernel firewall events, if available:")
    subprocess.run(
        ["sudo", "journalctl", "-k", "-g", "KaliGuard blocked:",
         "-n", "20", "--no-pager"],
        check=False,
    )

def save_preset():
    name = input("Preset name (letters, numbers, _ or -): ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name):
        print("Invalid preset name.")
        return
    path = PRESETS / f"{name}.json"
    if path.exists() and input("Overwrite it? [y/N] ").lower() != "y":
        return
    path.write_text(json.dumps(load_state(), indent=2))
    audit(f"Saved preset {name}")

def load_preset():
    name = input("Preset name to restore: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name):
        print("Invalid preset name.")
        return
    path = PRESETS / f"{name}.json"
    if not path.is_file():
        print("Preset not found.")
        return
    state = json.loads(path.read_text())
    # Validate every address and port before touching the firewall.
    state["blocked_ips"] = [
        str(ipaddress.IPv4Address(a)) for a in state["blocked_ips"]
    ]
    for item in state["ports"]:
        if item["protocol"] not in ("tcp", "udp"):
            raise ValueError("Invalid protocol in preset")
        if not 1 <= int(item["port"]) <= 65535:
            raise ValueError("Invalid port in preset")
    print("Restoring this preset replaces KaliGuard's current rules.")
    if input("Continue? [y/N] ").lower() != "y":
        return
    apply_state(state)
    save_state(state)
    audit(f"Restored preset {name}")

def main():
    if not shutil.which("nft") or not shutil.which("sudo"):
        raise RuntimeError("Install nftables and sudo first.")
    ensure_firewall()
    while True:
        print("""
=== KaliGuard Firewall Manager ===
1. List rules
2. Block IPv4 address
3. Unblock IPv4 address
4. Add TCP/UDP port accept rule
5. Monitor connections and listening ports
6. View audit and kernel logs
7. Save preset
8. Restore preset
9. Exit
""")
        choice = input("Select: ").strip()
        actions = {
            "1": list_rules,
            "2": add_block,
            "3": remove_block,
            "4": add_port_rule,
            "5": monitor,
            "6": show_logs,
            "7": save_preset,
            "8": load_preset,
        }
        if choice == "0":
            break
        action = actions.get(choice)
        if not action:
            print("Invalid choice.")
            continue
        try:
            action()
        except (ValueError, json.JSONDecodeError) as exc:
            print("Invalid input or saved data:", exc)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            print("Operation failed:", exc)

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        print("KaliGuard could not start:", exc)
        cd ~/kaliguard
source .venv/bin/activate
python3 kaliguard.py
