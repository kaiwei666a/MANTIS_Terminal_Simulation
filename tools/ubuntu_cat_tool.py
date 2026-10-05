"""Interactive cat input redirection and echo."""

from typing import List


def run_cat_stdin_redirect(abs_path: str, append: bool, *, chan, read_file, write_file, send) -> bool:
    old_timeout = None
    try:
        try:
            old_timeout = chan.gettimeout()
        except Exception:
            old_timeout = None
        chan.settimeout(None)
        prefix = read_file(abs_path) if append else ""
        write_file(abs_path, prefix)
        collected: List[str] = []
        while True:
            data = chan.recv(1)
            if not data:
                break
            char = data.decode("utf-8", errors="ignore")
            if char == "\x04":
                break
            if char == "\x03":
                send(chan, "^C\r\n")
                write_file(abs_path, prefix + "".join(collected))
                return False
            if char in {"\r", "\n"}:
                if char == "\r":
                    collected.append("\n")
                    send(chan, "\r\n")
                continue
            if char == "\x7f":
                if collected and collected[-1] != "\n":
                    collected.pop()
                    send(chan, "\b \b")
                continue
            collected.append(char)
            send(chan, char)
        write_file(abs_path, prefix + "".join(collected))
        if not collected or collected[-1] != "\n":
            send(chan, "\r\n")
        return True
    finally:
        try:
            chan.settimeout(old_timeout)
        except Exception:
            pass
