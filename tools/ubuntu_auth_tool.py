"""Interactive sudo/su password prompts."""

import re
from typing import List


def prompt_sudo_password(cmd: str, *, chan, system_log, login_username, password: str, recv_key, send) -> bool:

    old_timeout = None
    try:
        old_timeout = chan.gettimeout()
    except Exception:
        pass
    try:
        chan.settimeout(None)
    except Exception:
        pass
    try:
        active_user = str((system_log.get("identity") or {}).get("user") or login_username)
        is_su = bool(re.match(r"^\s*su\b", cmd))
        prompt_text = "Password: " if is_su else f"[sudo] password for {active_user}: "
        fail_text = "su: Authentication failure\r\n" if is_su else "sudo: 3 incorrect password attempts\r\n"
        for attempt in range(3):
            send(chan, prompt_text)
            pw_chars: List[str] = []
            while True:
                k = recv_key()
                if k == "":
                    return False
                if k in ("\r", "\n"):
                    break
                if k == "\x03":
                    send(chan, "^C\r\n")
                    return False
                if k == "\x7f":
                    if pw_chars:
                        pw_chars.pop()
                    continue
                if len(k) == 1 and (k.isprintable() or k == " "):
                    pw_chars.append(k)
            send(chan, "\r\n")
            if "".join(pw_chars) == password:
                return True
            if attempt < 2:
                send(chan, "Sorry, try again.\r\n")
        send(chan, fail_text)
        return False
    finally:
        try:
            chan.settimeout(old_timeout)
        except Exception:
            pass
