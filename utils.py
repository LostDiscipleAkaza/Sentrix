"""
Shared utilities, structured logging, and ASCII frame rendering for Sentrix.
"""

import datetime
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional


def load_env(env_path: str = ".env") -> None:
    """
    Loads environment variables from a .env file into os.environ.
    Uses python-dotenv if available, and falls back to a clean native parser.
    """
    try:
        import dotenv
        dotenv.load_dotenv(env_path)
        return
    except ImportError:
        pass

    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
    except Exception:
        pass


# Automatically load .env on import
load_env()


class ColorCodes:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def strip_ansi(text: str) -> str:
    """Strips ANSI escape codes from string for accurate display width calculation."""
    ansi_regex = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_regex.sub("", text)


class ColoredFormatter(logging.Formatter):
    """Custom logging formatter with ANSI color codes."""

    LEVEL_COLORS = {
        logging.DEBUG: ColorCodes.DIM + ColorCodes.WHITE,
        logging.INFO: ColorCodes.CYAN,
        logging.WARNING: ColorCodes.YELLOW,
        logging.ERROR: ColorCodes.RED,
        logging.CRITICAL: ColorCodes.BOLD + ColorCodes.RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelno, ColorCodes.RESET)
        time_str = datetime.datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        prefix = f"{ColorCodes.DIM}[{time_str}]{ColorCodes.RESET} {color}[{record.levelname[:4]}]{ColorCodes.RESET}"
        return f"{prefix} {record.getMessage()}"


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configures and returns the main application logger."""
    logger = logging.getLogger("sentrix")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColoredFormatter())
        logger.addHandler(handler)

    return logger


def current_timestamp() -> str:
    """Returns current ISO 8601 timestamp string."""
    return datetime.datetime.now().isoformat(timespec="seconds")


def safe_get(dictionary: Dict[str, Any], key: str, default: Any = "") -> Any:
    """Safely retrieves a value from a dictionary, returning default if None or missing."""
    if not isinstance(dictionary, dict):
        return default
    value = dictionary.get(key)
    if value is None:
        return default
    return value


# ---------------------------------------------------------------------------
# CLI ASCII Tool Frames & Box Drawing
# ---------------------------------------------------------------------------

def print_banner(version: str = "2.1.0") -> None:
    """Prints a styled terminal banner enclosed in an ASCII tool frame."""
    logo = r"""  ____             _        _      
 / ___|  ___ _ __ | |_ _ __(_)_  __
 \___ \ / _ \ '_ \| __| '__| \ \/ /
  ___) |  __/ | | | |_| |  | |>  < 
 |____/ \___|_| |_|\__|_|  |_/_/\_\ """

    width = 76
    top_line = f"{ColorCodes.CYAN}╔{'═' * (width - 2)}╗{ColorCodes.RESET}"
    bottom_line = f"{ColorCodes.CYAN}╚{'═' * (width - 2)}╝{ColorCodes.RESET}"
    sep_line = f"{ColorCodes.CYAN}╠{'═' * (width - 2)}╣{ColorCodes.RESET}"

    print(top_line)
    for line in logo.split("\n"):
        pad = width - 4 - len(line)
        print(f"{ColorCodes.CYAN}║{ColorCodes.RESET} {ColorCodes.BOLD}{line}{ColorCodes.RESET}{' ' * max(0, pad)} {ColorCodes.CYAN}║{ColorCodes.RESET}")

    print(sep_line)
    subtitle = f"Sentrix: Advanced Network Reconnaissance & Threat Assessment Pipeline v{version}"
    pad_sub = width - 4 - len(subtitle)
    print(f"{ColorCodes.CYAN}║{ColorCodes.RESET} {ColorCodes.YELLOW}{subtitle}{ColorCodes.RESET}{' ' * max(0, pad_sub)} {ColorCodes.CYAN}║{ColorCodes.RESET}")

    caps = "Targets: IPv4 | IPv6 | CIDRs | Passive CT DNS | AXFR | NVD | CIRCL | Shodan"
    pad_caps = width - 4 - len(caps)
    print(f"{ColorCodes.CYAN}║{ColorCodes.RESET} {ColorCodes.DIM}{caps}{ColorCodes.RESET}{' ' * max(0, pad_caps)} {ColorCodes.CYAN}║{ColorCodes.RESET}")
    print(bottom_line + "\n")


def draw_frame(title: str, lines: List[str], width: int = 76, color: str = ColorCodes.CYAN) -> str:
    """
    Renders lines of text enclosed in a classic single-line ASCII frame.
    ┌─[ TITLE ]──────────────────────────────────┐
    │ Content line                               │
    └────────────────────────────────────────────┘
    """
    clean_title = strip_ansi(title)
    max_line_len = max([len(strip_ansi(l)) for l in lines] + [len(clean_title) + 6]) if lines else len(clean_title) + 6
    width = max(width, max_line_len + 4)
    title_part = f"─[ {title} ]"
    clean_title_part = f"─[ {clean_title} ]"
    remain = width - 2 - len(clean_title_part)
    top = f"{color}┌{title_part}{'─' * max(0, remain)}┐{ColorCodes.RESET}"
    bottom = f"{color}└{'─' * (width - 2)}┘{ColorCodes.RESET}"

    body_lines = []
    for line in lines:
        clean_len = len(strip_ansi(line))
        pad = width - 4 - clean_len
        body_lines.append(f"{color}│{ColorCodes.RESET} {line}{' ' * max(0, pad)} {color}│{ColorCodes.RESET}")

    return "\n" + "\n".join([top] + body_lines + [bottom]) + "\n"


def draw_section_header(title: str, width: int = 76, color: str = ColorCodes.CYAN) -> None:
    """Prints a styled section separator with an ASCII bracket."""
    clean_title = strip_ansi(title)
    prefix = f"{color}┌──[ {ColorCodes.BOLD}{title}{ColorCodes.RESET}{color} ]"
    remain = width - len(clean_title) - 7
    print(f"\n{prefix}{'─' * max(0, remain)}┐{ColorCodes.RESET}")


def draw_section_footer(width: int = 76, color: str = ColorCodes.CYAN) -> None:
    """Prints the closing frame for a section."""
    print(f"{color}└──{'─' * (width - 5)}┘{ColorCodes.RESET}\n")


def format_table(headers: List[str], rows: List[List[str]]) -> str:
    """
    Renders a table enclosed in clean Unicode/ASCII box-drawing borders:
    ┌────────┬─────────┐
    │ Header │ Header  │
    ├────────┼─────────┤
    │ Row    │ Row     │
    └────────┴─────────┘
    """
    if not rows:
        return ""

    col_widths = [len(strip_ansi(h)) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            if idx < len(col_widths):
                col_widths[idx] = max(col_widths[idx], len(strip_ansi(str(cell))))

    # Box drawing elements
    c_tl, c_tm, c_tr = "┌", "┬", "┐"
    c_ml, c_mm, c_mr = "├", "┼", "┤"
    c_bl, c_bm, c_br = "└", "┴", "┘"
    c_h, c_v = "─", "│"

    top_border = c_tl + c_tm.join(c_h * (w + 2) for w in col_widths) + c_tr
    mid_border = c_ml + c_mm.join(c_h * (w + 2) for w in col_widths) + c_mr
    bot_border = c_bl + c_bm.join(c_h * (w + 2) for w in col_widths) + c_br

    header_cells = [
        f" {ColorCodes.BOLD}{headers[i]}{ColorCodes.RESET}{' ' * (col_widths[i] - len(strip_ansi(headers[i])))} "
        for i in range(len(headers))
    ]
    header_line = f"{c_v}" + f"{c_v}".join(header_cells) + f"{c_v}"

    row_lines = []
    for row in rows:
        cells = []
        for i, val in enumerate(row):
            val_str = str(val)
            clean_len = len(strip_ansi(val_str))
            pad = col_widths[i] - clean_len
            cells.append(f" {val_str}{' ' * max(0, pad)} ")
        row_lines.append(f"{c_v}" + f"{c_v}".join(cells) + f"{c_v}")

    return "\n" + "\n".join([top_border, header_line, mid_border] + row_lines + [bot_border]) + "\n"
