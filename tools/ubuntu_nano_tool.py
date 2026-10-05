"""Interactive nano editor and terminal rendering."""

from typing import List, Tuple

CSI = "\x1b["


def _clip(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _nano_terminal_size(terminal_state) -> Tuple[int, int]:
    rows = max(5, int(getattr(terminal_state, "pty_height", 24) or 24))
    cols = max(20, int(getattr(terminal_state, "pty_width", 80) or 80))
    return rows, cols


def _nano_move_cursor(row: int, col: int, *, chan, send):
    send(chan, f"{CSI}{row};{col}H")


def render_nano(filename: str, lines: List[str], cy: int, cx: int, msg: str, dirty: bool, *, chan, terminal_state, send):
    rows, cols = _nano_terminal_size(terminal_state)
    text_rows = max(1, rows - 3)
    top = 0
    if cy >= top + text_rows:
        top = cy - text_rows + 1
    if cy < top:
        top = cy

    head = f"  GNU nano  {filename}"
    if dirty:
        head += "  [Modified]"
    screen_lines = [head]
    for r in range(text_rows):
        li = top + r
        screen_lines.append(lines[li] if li < len(lines) else "")
    screen_lines.extend(("^O WriteOut   ^X Exit", msg or ""))

    frame = ["\x1b[?25l"]
    for row, text in enumerate(screen_lines, start=1):
        frame.append(f"{CSI}{row};1H{text[:cols]}{CSI}K")
    send(chan, "".join(frame))

    vy = 2 + (cy - top)
    vx = 1 + cx
    vy = _clip(vy, 2, rows - 2)
    vx = _clip(vx, 1, cols)
    _nano_move_cursor(vy, vx, chan=chan, send=send)
    send(chan, "\x1b[?25h")


def run_nano_interactive(abs_path: str, *, chan, terminal_state, read_file, write_file, recv_key, send):
    def draw(filename, lines, cy, cx, msg, dirty):
        render_nano(filename, lines, cy, cx, msg, dirty, chan=chan, terminal_state=terminal_state, send=send)


    old_timeout = None
    alternate_screen = False
    try:
        try:
            old_timeout = chan.gettimeout()
        except Exception:
            old_timeout = None
        try:
            chan.settimeout(None)
        except Exception:
            pass

        filename = abs_path
        content = read_file(abs_path)
        lines = content.split("\n")
        if not lines:
            lines = [""]

        cy, cx = 0, 0
        dirty = False
        msg = ""

        send(chan, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")
        alternate_screen = True
        draw(filename, lines, cy, cx, msg, dirty)

        while True:
            k = recv_key()
            if k == "":
                break

            if k == "\x18":
                if not dirty:
                    msg = "Exit"
                    draw(filename, lines, cy, cx, msg, dirty)
                    break

                msg = "Save modified buffer? (y/n)"
                draw(filename, lines, cy, cx, msg, dirty)
                while True:
                    kk = recv_key().lower()
                    if kk in ("y", "n"):
                        if kk == "y":
                            try:
                                write_file(abs_path, "\n".join(lines))
                                dirty = False
                                msg = "Wrote file"
                            except PermissionError:
                                msg = "Error writing file: Permission denied"
                            except Exception as e:
                                msg = f"Error writing file: {e}"
                        else:
                            msg = "Discarded changes"
                        draw(filename, lines, cy, cx, msg, dirty)
                        break
                break


            if k == "\x0f":
                try:
                    write_file(abs_path, "\n".join(lines))
                    dirty = False
                    msg = "Wrote file"
                except PermissionError:
                    msg = "Error writing file: Permission denied"
                except Exception as e:
                    msg = f"Error writing file: {e}"
                draw(filename, lines, cy, cx, msg, dirty)
                continue

            if k == "\x1b[A":
                cy = _clip(cy - 1, 0, len(lines) - 1)
                cx = _clip(cx, 0, len(lines[cy]))
                draw(filename, lines, cy, cx, "", dirty)
                continue
            if k == "\x1b[B":
                cy = _clip(cy + 1, 0, len(lines) - 1)
                cx = _clip(cx, 0, len(lines[cy]))
                draw(filename, lines, cy, cx, "", dirty)
                continue
            if k == "\x1b[C":
                cx = _clip(cx + 1, 0, len(lines[cy]))
                draw(filename, lines, cy, cx, "", dirty)
                continue
            if k == "\x1b[D":
                cx = _clip(cx - 1, 0, len(lines[cy]))
                draw(filename, lines, cy, cx, "", dirty)
                continue

            if k in ("\r", "\n"):
                left = lines[cy][:cx]
                right = lines[cy][cx:]
                lines[cy] = left
                lines.insert(cy + 1, right)
                cy += 1
                cx = 0
                dirty = True
                draw(filename, lines, cy, cx, "", dirty)
                continue


            if k == "\x7f":
                if cx > 0:
                    s = lines[cy]
                    lines[cy] = s[:cx - 1] + s[cx:]
                    cx -= 1
                    dirty = True
                elif cy > 0:
                    prev = lines[cy - 1]
                    cur = lines[cy]
                    cx = len(prev)
                    lines[cy - 1] = prev + cur
                    del lines[cy]
                    cy -= 1
                    dirty = True
                draw(filename, lines, cy, cx, "", dirty)
                continue

            if len(k) == 1 and (" " <= k <= "~"):
                s = lines[cy]
                lines[cy] = s[:cx] + k + s[cx:]
                cx += 1
                dirty = True
                draw(filename, lines, cy, cx, "", dirty)
                continue

    finally:
        if alternate_screen:
            send(chan, "\x1b[0m\x1b[?25h\x1b[?1049l\r\x1b[K")
        else:
            send(chan, "\x1b[?25h")
        try:
            chan.settimeout(old_timeout)
        except Exception:
            pass
