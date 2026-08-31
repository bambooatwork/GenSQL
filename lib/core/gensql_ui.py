#!/usr/bin/env python
"""
GenSQL UI Engine
Author  : Jeevraj
Version : 2.0.0

Completely replaces sqlmap's logging output with GenSQL's own format.
Intercepts Python logging and dataToStdout to produce a totally different look.
"""

import sys
import os
import time
import logging
import threading
import re

# ── GenSQL color palette ──────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    # Bright neon palette — nothing like sqlmap's simple colors
    CYAN    = "\033[38;5;51m"    # electric cyan
    GREEN   = "\033[38;5;82m"    # bright green
    YELLOW  = "\033[38;5;220m"   # gold yellow
    RED     = "\033[38;5;196m"   # bright red
    PURPLE  = "\033[38;5;135m"   # purple
    BLUE    = "\033[38;5;39m"    # sky blue
    ORANGE  = "\033[38;5;208m"   # orange
    GRAY    = "\033[38;5;245m"   # medium gray
    WHITE   = "\033[38;5;255m"   # bright white
    PINK    = "\033[38;5;213m"   # pink

    # Backgrounds
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"

    @staticmethod
    def supports_color():
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# ── GenSQL log level tags ─────────────────────────────────────────────────────
# Map sqlmap levels → GenSQL styled tags (completely different appearance)
LEVEL_MAP = {
    logging.DEBUG:    (C.GRAY,   "DBG"),
    logging.INFO:     (C.CYAN,   " ~ "),
    logging.WARNING:  (C.YELLOW, " ! "),
    logging.ERROR:    (C.RED,    "ERR"),
    logging.CRITICAL: (C.RED + C.BOLD, "!!!"),
}

# Phrases that sqlmap emits — replace with GenSQL equivalents
MESSAGE_REWRITES = {
    # sqlmap branding removal
    r"sqlmap": "gensql",
    r"SQLMap": "GenSQL",
    r"SQLMAP": "GENSQL",

    # WAF detection
    r"previous heuristics detected that the target is protected by some kind of WAF/IPS":
        "WAF/IPS detected on target — activating evasion layer",

    # SQL injection messages
    r"testing if the target URL content is stable":
        "probing baseline response stability",
    r"target URL content is stable":
        "baseline established — target is stable",
    r"testing if (GET|POST) parameter '(.+?)' is dynamic":
        r"probing parameter \2 for reflection",
    r"GET parameter '(.+?)' appears to be dynamic":
        r"parameter \1 is dynamic — candidate for injection",
    r"POST parameter '(.+?)' appears to be dynamic":
        r"parameter \1 (POST) is dynamic — candidate for injection",
    r"testing for SQL injection on (GET|POST) parameter '(.+?)'":
        r"scanning parameter \2 for injection vectors",
    r"possible integer casting detected":
        "numeric type casting detected — switching to integer-safe vectors",
    r"heuristic \(basic\) test shows that (GET|POST) parameter '(.+?)' might be injectable":
        r"heuristic hit: \2 may be injectable (needs confirmation)",
    r"it looks like the back-end DBMS is '(.+?)'":
        r"DBMS fingerprint: \1",
    r"parameter '(.+?)' is vulnerable":
        r"[CONFIRMED] parameter \1 is injectable",
    r"parameter '(.+?)' appears to be '(.+?)' injectable":
        r"[CONFIRMED] \1 → \2",
    r"testing connection to the target URL":
        "establishing connection to target",
    r"fetching database names":
        "enumerating databases",
    r"fetching tables for database: '(.+?)'":
        r"enumerating tables in \1",
    r"fetching columns for table '(.+?)' in database '(.+?)'":
        r"mapping columns: \2.\1",
    r"fetching entries for table '(.+?)' in database '(.+?)'":
        r"extracting data: \2.\1",
    r"you can find results of scanning in multiple targets mode":
        "multi-target results saved",

    # Network
    r"can't establish SSL connection":
        "SSL handshake failed — retrying with relaxed ciphers",
    r"HTTP error codes detected during run:":
        "HTTP error summary:",

    # User prompts (--batch already answers these, but for display)
    r"Do you want to use those": "using target cookies",
    r"do you want to skip those kind of cases": "proceeding with integer-safe vectors",

    # Completion
    r"fetched data logged to text files under '(.+?)'":
        r"data saved → \1",
    r"ending @": "finished @",
}


def _rewrite(msg):
    """Apply all message rewrites to a log line."""
    for pattern, replacement in MESSAGE_REWRITES.items():
        try:
            msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
        except Exception:
            pass
    return msg


def _timestamp():
    """GenSQL timestamp format — different from sqlmap's HH:MM:SS"""
    t = time.time()
    ms = int((t % 1) * 1000)
    return time.strftime("%H:%M:%S") + ".%03d" % ms


# ── Custom logging handler ────────────────────────────────────────────────────

class GenSQLHandler(logging.Handler):
    """
    Drop-in replacement for sqlmap's LOGGER_HANDLER.
    Produces completely different visual output.
    """

    def __init__(self, use_color=True):
        super().__init__()
        self._color = use_color and C.supports_color()
        self._lock = threading.Lock()

    def emit(self, record):
        try:
            msg = self.format(record)
            self._write(record.levelno, msg)
        except Exception:
            pass

    def format(self, record):
        msg = record.getMessage()
        return _rewrite(str(msg))

    def _write(self, level, msg):
        color, tag = LEVEL_MAP.get(level, (C.GRAY, "   "))
        ts = _timestamp()

        if self._color:
            line = (
                C.GRAY + "[" + C.CYAN + ts + C.GRAY + "] "
                + C.GRAY + "[" + color + C.BOLD + tag + C.RESET + C.GRAY + "] "
                + C.RESET + msg + C.RESET
            )
        else:
            line = "[%s] [%s] %s" % (ts, tag.strip(), msg)

        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()


# ── Progress bar ──────────────────────────────────────────────────────────────

class ProgressBar:
    """Animated progress bar for dump operations."""

    def __init__(self, total, label="", width=40):
        self._total = max(total, 1)
        self._label = label
        self._width = width
        self._current = 0
        self._start = time.time()
        self._lock = threading.Lock()

    def update(self, n=1):
        with self._lock:
            self._current = min(self._current + n, self._total)
            self._render()

    def set(self, n):
        with self._lock:
            self._current = min(n, self._total)
            self._render()

    def _render(self):
        pct = self._current / self._total
        filled = int(self._width * pct)
        bar = "█" * filled + "░" * (self._width - filled)
        elapsed = time.time() - self._start
        eta = (elapsed / max(self._current, 1)) * (self._total - self._current)
        line = (
            "\r"
            + C.GRAY + "  ["
            + C.GREEN + bar
            + C.GRAY + "] "
            + C.WHITE + "%3d%%" % int(pct * 100)
            + C.GRAY + "  %d/%d" % (self._current, self._total)
            + C.YELLOW + "  ETA %ds" % int(eta)
            + C.GRAY + "  %s" % self._label
            + C.RESET
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def done(self):
        with self._lock:
            self._current = self._total
            self._render()
            sys.stdout.write("\n")
            sys.stdout.flush()


# ── Output helpers ────────────────────────────────────────────────────────────

def banner_line(text="", char="─", width=76):
    """Print a GenSQL-style section separator."""
    if text:
        pad = max(0, width - len(text) - 4)
        line = C.GRAY + "  ── " + C.CYAN + text + C.GRAY + " " + char * pad + C.RESET
    else:
        line = C.GRAY + "  " + char * width + C.RESET
    sys.stdout.write(line + "\n")
    sys.stdout.flush()

def success(msg):
    ts = _timestamp()
    sys.stdout.write(
        C.GRAY + "[" + C.CYAN + ts + C.GRAY + "] "
        "[" + C.GREEN + C.BOLD + " + " + C.RESET + C.GRAY + "] "
        + C.GREEN + msg + C.RESET + "\n")
    sys.stdout.flush()

def warn(msg):
    ts = _timestamp()
    sys.stdout.write(
        C.GRAY + "[" + C.CYAN + ts + C.GRAY + "] "
        "[" + C.YELLOW + C.BOLD + " ! " + C.RESET + C.GRAY + "] "
        + C.YELLOW + msg + C.RESET + "\n")
    sys.stdout.flush()

def info(msg):
    ts = _timestamp()
    sys.stdout.write(
        C.GRAY + "[" + C.CYAN + ts + C.GRAY + "] "
        "[" + C.CYAN + C.BOLD + " ~ " + C.RESET + C.GRAY + "] "
        + C.WHITE + msg + C.RESET + "\n")
    sys.stdout.flush()

def error(msg):
    ts = _timestamp()
    sys.stdout.write(
        C.GRAY + "[" + C.CYAN + ts + C.GRAY + "] "
        "[" + C.RED + C.BOLD + "ERR" + C.RESET + C.GRAY + "] "
        + C.RED + msg + C.RESET + "\n")
    sys.stdout.flush()

def fatal(msg):
    ts = _timestamp()
    sys.stdout.write(
        C.GRAY + "[" + C.CYAN + ts + C.GRAY + "] "
        "[" + C.RED + C.BOLD + "!!!" + C.RESET + C.GRAY + "] "
        + C.RED + C.BOLD + msg + C.RESET + "\n")
    sys.stdout.flush()

def found(label, value):
    """Print a 'found' result line."""
    ts = _timestamp()
    sys.stdout.write(
        C.GRAY + "[" + C.CYAN + ts + C.GRAY + "] "
        "[" + C.GREEN + C.BOLD + " + " + C.RESET + C.GRAY + "] "
        + C.CYAN + "%-20s" % label + C.RESET
        + C.GRAY + " → " + C.GREEN + C.BOLD + str(value)
        + C.RESET + "\n")
    sys.stdout.flush()

def table(headers, rows, title=""):
    """Print a formatted result table."""
    if title:
        banner_line(title)

    # Calculate column widths
    col_w = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_w[i] = max(col_w[i], len(str(cell)))

    # Header
    sep = C.GRAY + "  ┼─" + "─┼─".join("─" * w for w in col_w) + "─┼" + C.RESET
    hdr = C.GRAY + "  │ " + C.CYAN + C.BOLD
    hdr += (" │ ".join("%-*s" % (col_w[i], headers[i]) for i in range(len(headers))))
    hdr += C.RESET + C.GRAY + " │" + C.RESET

    sys.stdout.write("\n" + sep + "\n" + hdr + "\n" + sep + "\n")

    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            v = str(cell)
            # Colorize specific data types
            if re.match(r"^[0-9a-f]{32}$", v, re.I):
                v = C.ORANGE + v + C.RESET  # hashes in orange
            elif "@" in v and "." in v:
                v = C.BLUE + v + C.RESET    # emails in blue
            elif re.match(r"^\$2[ab]\$", v):
                v = C.RED + v + C.RESET     # bcrypt in red
            else:
                v = C.WHITE + v + C.RESET
            cells.append(C.GRAY + "%-*s" % (col_w[i], "") + C.RESET)
            # Rebuild properly
            cells[-1] = "%-*s" % (col_w[i], str(cell))

        line = C.GRAY + "  │ " + C.RESET
        line += (C.GRAY + " │ " + C.RESET).join(
            C.WHITE + "%-*s" % (col_w[i], str(row[i])) + C.RESET
            for i in range(len(row)))
        line += C.GRAY + " │" + C.RESET
        sys.stdout.write(line + "\n")

    sys.stdout.write(sep + "\n\n")
    sys.stdout.flush()


# ── Install the handler ───────────────────────────────────────────────────────

_INSTALLED = False

def install(verbose=False):
    """
    Install the GenSQL logging handler, replacing sqlmap's default handler.
    Call this early in gensql.py before any logging occurs.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True

    # Get the root sqlmap logger
    root_logger = logging.getLogger("sqlmap")

    # Remove all existing handlers
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    # Install ours
    handler = GenSQLHandler(use_color=True)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    root_logger.addHandler(handler)
    root_logger.propagate = False

    # Also patch the global LOGGER_HANDLER in lib.core.data
    try:
        from lib.core import data as _data
        if hasattr(_data, "LOGGER_HANDLER"):
            _data.LOGGER_HANDLER = handler
    except Exception:
        pass

    # Patch dataToStdout to rewrite sqlmap branding from any remaining direct output
    try:
        import lib.core.common as _common
        _orig_dataToStdout = _common.dataToStdout

        def _patched_dataToStdout(data, forceOutput=False, bold=False, level=logging.INFO, **kw):
            # Rewrite sqlmap references
            if isinstance(data, str):
                data = _rewrite(data)
                # Convert sqlmap-style timestamps: [HH:MM:SS] [INFO] → GenSQL style
                data = re.sub(
                    r"\[(\d{2}:\d{2}:\d{2})\] \[(INFO|WARNING|ERROR|CRITICAL|DEBUG)\] ",
                    lambda m: _convert_sqlmap_log(m.group(1), m.group(2)),
                    data
                )
            return _orig_dataToStdout(data, forceOutput=forceOutput, bold=bold, level=level, **kw)

        _common.dataToStdout = _patched_dataToStdout
    except Exception:
        pass


def _convert_sqlmap_log(ts_str, level_str):
    """Convert sqlmap-style '[HH:MM:SS] [INFO]' to GenSQL style."""
    level_map = {
        "INFO":     (" ~ ", C.CYAN),
        "WARNING":  (" ! ", C.YELLOW),
        "ERROR":    ("ERR", C.RED),
        "CRITICAL": ("!!!", C.RED + C.BOLD),
        "DEBUG":    ("DBG", C.GRAY),
    }
    tag, color = level_map.get(level_str, ("   ", C.GRAY))
    return (
        C.GRAY + "[" + C.CYAN + ts_str + C.GRAY + "] "
        + C.GRAY + "[" + color + C.BOLD + tag + C.RESET + C.GRAY + "] " + C.RESET
    )


# ── Scan result printer ───────────────────────────────────────────────────────

def print_injection_found(param, technique, dbms, payload):
    """Print a highlighted 'injection found' block."""
    width = 70
    sys.stdout.write("\n")
    sys.stdout.write(C.GREEN + C.BOLD + "  ╔" + "═" * (width - 2) + "╗\n")
    sys.stdout.write("  ║  ⚡ INJECTION CONFIRMED" + " " * (width - 28) + "║\n")
    sys.stdout.write("  ╠" + "═" * (width - 2) + "╣\n")
    sys.stdout.write("  ║  Parameter : " + C.WHITE + "%-*s" % (width - 18, param) + C.GREEN + "║\n")
    sys.stdout.write("  ║  Technique : " + C.WHITE + "%-*s" % (width - 18, technique) + C.GREEN + "║\n")
    sys.stdout.write("  ║  DBMS      : " + C.WHITE + "%-*s" % (width - 18, dbms) + C.GREEN + "║\n")
    sys.stdout.write("  ║  Payload   : " + C.YELLOW + "%-*s" % (width - 18, payload[:width-18]) + C.GREEN + "║\n")
    sys.stdout.write("  ╚" + "═" * (width - 2) + "╝\n" + C.RESET)
    sys.stdout.flush()


def print_dump_table(table_name, columns, rows):
    """Print a dump result table with GenSQL styling."""
    banner_line("TABLE: %s  (%d rows)" % (table_name, len(rows)))
    if not rows:
        warn("No data retrieved from %s" % table_name)
        return

    # Print header
    col_w = [len(c) for c in columns]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_w):
                col_w[i] = max(col_w[i], len(str(cell)[:60]))

    def _sep(char="─"):
        return C.GRAY + "  ├─" + "─┼─".join(char * w for w in col_w) + "─┤" + C.RESET

    def _top():
        return C.GRAY + "  ┌─" + "─┬─".join("─" * w for w in col_w) + "─┐" + C.RESET

    def _bot():
        return C.GRAY + "  └─" + "─┴─".join("─" * w for w in col_w) + "─┘" + C.RESET

    sys.stdout.write(_top() + "\n")

    hdr_cells = (
        C.GRAY + " │ " + C.RESET
    ).join(C.CYAN + C.BOLD + "%-*s" % (col_w[i], columns[i]) + C.RESET
           for i in range(len(columns)))
    sys.stdout.write(C.GRAY + "  │ " + C.RESET + hdr_cells + C.GRAY + " │" + C.RESET + "\n")
    sys.stdout.write(_sep("─") + "\n")

    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            v = str(cell)[:60]
            # Smart coloring by value type
            if re.match(r"^[0-9a-f]{32}$", v, re.I) or re.match(r"^[0-9a-f]{40}$", v, re.I):
                colored = C.ORANGE + v
            elif re.match(r"^\$2[aby]?\$", v):
                colored = C.RED + v
            elif "@" in v and "." in v:
                colored = C.BLUE + v
            elif v.isdigit():
                colored = C.PURPLE + v
            else:
                colored = C.WHITE + v
            cells.append(colored + C.RESET)

        row_line = C.GRAY + "  │ " + C.RESET
        row_line += (C.GRAY + " │ " + C.RESET).join(
            cells[i] + C.RESET + " " * max(0, col_w[i] - len(str(row[i])[:60]))
            for i in range(min(len(cells), len(col_w))))
        row_line += C.GRAY + " │" + C.RESET
        sys.stdout.write(row_line + "\n")

    sys.stdout.write(_bot() + "\n\n")
    sys.stdout.flush()
