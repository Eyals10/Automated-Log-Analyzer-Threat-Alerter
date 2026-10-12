"""Generate a realistic synthetic /var/log/auth.log for testing the detector.

The output mimics real Ubuntu/OpenSSH logs: PAM noise, rsyslog "message repeated"
compression, invalid-user probing, an IPv6 attacker, a brute force that ends in a
successful login, a legitimate admin who mistypes a password, and decoy
"Failed password" lines from non-SSH services that must be ignored.

Only documentation/private address space is used (RFC 5737, RFC 3849, RFC 1918)
so no real host is implicated. The exact expected failure count per IP is
written to expected_failed_logins.json, which the unit tests check against.

    python3 sample_logs/generate_sample_log.py
"""
import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent

random.seed(1337)
HOST = "web-prod-01"
START = datetime(2026, 10, 11, 0, 0, 0)
lines = []          # (datetime, text)
truth = {}          # ip -> expected failed count
pid = [20000]


def next_pid():
    pid[0] += random.randint(1, 7)
    return pid[0]


def add(dt, proc, msg):
    lines.append((dt, f"{dt.strftime('%b %e %H:%M:%S')} {HOST} {proc}: {msg}"))


def bump(ip, n=1):
    truth[ip] = truth.get(ip, 0) + n


def session(dt, ip, user, attempts, invalid=False, use_repeat=False):
    """One SSH connection with several password attempts (bots try up to MaxAuthTries)."""
    p = next_pid()
    port = random.randint(30000, 65000)
    sshd = f"sshd[{p}]"
    if invalid:
        add(dt, sshd, f"Invalid user {user} from {ip} port {port}")
        add(dt, sshd, "pam_unix(sshd:auth): check pass; user unknown")
    add(dt, sshd, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
                  f"tty=ssh ruser= rhost={ip}" + ("" if invalid else f"  user={user}"))
    who = f"invalid user {user}" if invalid else user
    t = dt + timedelta(seconds=2)
    add(t, sshd, f"Failed password for {who} from {ip} port {port} ssh2")
    bump(ip)
    remaining = attempts - 1
    if remaining > 0:
        if use_repeat:
            t += timedelta(seconds=2 * remaining)
            add(t, sshd, f"message repeated {remaining} times: [ Failed password for {who} from {ip} port {port} ssh2]")
            bump(ip, remaining)
        else:
            for _ in range(remaining):
                t += timedelta(seconds=random.randint(2, 4))
                add(t, sshd, f"Failed password for {who} from {ip} port {port} ssh2")
                bump(ip)
    if attempts >= 6:
        add(t, sshd, f"error: maximum authentication attempts exceeded for {who} from {ip} port {port} ssh2 [preauth]")
        add(t, sshd, f"Disconnecting {'invalid' if invalid else 'authenticating'} user {user} {ip} port {port}: "
                     "Too many authentication failures [preauth]")
        add(t, sshd, f"PAM {attempts - 1} more authentication failures; logname= uid=0 euid=0 tty=ssh "
                     f"ruser= rhost={ip}" + ("" if invalid else f"  user={user}"))
    else:
        add(t, sshd, f"Connection closed by {'invalid' if invalid else 'authenticating'} user {user} {ip} port {port} [preauth]")
    return t


# --- 1. Heavy root brute-force (uses rsyslog "message repeated" compression) --------
t = START + timedelta(hours=2, minutes=13)
for _ in range(60):
    t = session(t, "203.0.113.45", "root", 6, use_repeat=random.random() < 0.5)
    t += timedelta(seconds=random.randint(5, 40))

# --- 2. Username dictionary attack ------------------------------------------------
dict_users = ["admin", "test", "oracle", "ubuntu", "postgres", "git", "user", "ftpuser",
              "guest", "pi", "hadoop", "minecraft", "deploy", "jenkins", "support"]
t = START + timedelta(hours=5, minutes=2)
for _ in range(40):
    t = session(t, "198.51.100.77", random.choice(dict_users), random.randint(1, 3), invalid=True)
    t += timedelta(seconds=random.randint(3, 20))

# --- 3. Low-and-slow: 8 attempts spread over ~8 hours -------------------------------
t = START + timedelta(hours=1)
for _ in range(8):
    session(t, "192.0.2.10", "root", 1)
    t += timedelta(minutes=random.randint(50, 70))

# --- 4. Below threshold: 3 attempts, never flagged ----------------------------------
session(START + timedelta(hours=9, minutes=30), "203.0.113.200", "admin", 3, invalid=True)

# --- 5. Brute force that SUCCEEDS (the scary one) -----------------------------------
t = START + timedelta(hours=14, minutes=41)
for _ in range(5):
    t = session(t, "198.51.100.9", "root", 5)
    t += timedelta(seconds=random.randint(5, 15))
p = next_pid()
add(t, f"sshd[{p}]", "Accepted password for root from 198.51.100.9 port 44122 ssh2")
add(t, f"sshd[{p}]", "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")
add(t, "systemd-logind[612]", "New session 4711 of user root.")

# --- 6. IPv6 attacker ----------------------------------------------------------------
t = START + timedelta(hours=18, minutes=5)
for _ in range(4):
    t = session(t, "2001:db8::bad:1", "ubuntu", 3, invalid=True)
    t += timedelta(seconds=30)

# --- 7. Legit admin: mistypes twice, then gets in (must NOT be flagged) --------------
t = START + timedelta(hours=8, minutes=55)
session(t, "10.0.4.22", "sysadmin", 2)
p = next_pid()
add(t + timedelta(seconds=12), f"sshd[{p}]", "Accepted password for sysadmin from 10.0.4.22 port 50544 ssh2")
for h in (9, 12, 16):
    p = next_pid()
    add(START + timedelta(hours=h, minutes=3), f"sshd[{p}]",
        "Accepted publickey for deploy from 10.0.4.30 port 41022 ssh2: ED25519 SHA256:q9Xk2b7Lr0aFhJ1nP4sT8vW3yZ6cE5dG2hK0mN7pQ1A")

# --- 8. Background noise (must all be ignored) ---------------------------------------
for minute in range(0, 24 * 60, 17):
    dt = START + timedelta(minutes=minute)
    p = next_pid()
    add(dt, f"CRON[{p}]", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
    add(dt + timedelta(seconds=1), f"CRON[{p}]", "pam_unix(cron:session): session closed for user root")
for h in range(0, 24, 3):
    dt = START + timedelta(hours=h, minutes=random.randint(0, 59))
    add(dt, "sudo", "    sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/apt update")
    add(dt, f"sshd[{next_pid()}]", f"Connection closed by 203.0.113.{random.randint(1, 254)} port {random.randint(30000, 65000)} [preauth]")
    add(dt, f"sshd[{next_pid()}]", "Received disconnect from 192.0.2.66 port 53120:11: Bye Bye [preauth]")
# A non-sshd service that also says "Failed password" -- must NOT be counted as SSH
add(START + timedelta(hours=11), "vsftpd[901]", "pam_unix(vsftpd:auth): Failed password for ftp from 192.0.2.99")
add(START + timedelta(hours=11, minutes=1), "dovecot[902]", "auth: Failed password for alice from 192.0.2.99 port 993")

lines.sort(key=lambda x: x[0])
log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "sample_auth.log"
truth_path = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "expected_failed_logins.json"
log_path.write_text("".join(text + "\n" for _, text in lines))
truth_path.write_text(json.dumps(truth, indent=2) + "\n")
print(f"wrote {len(lines)} lines to {log_path.name}; expected failures per IP: {truth}")
