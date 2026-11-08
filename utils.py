"""
Shared utilities, structured logging, and console formatting for Reconnoiter.
"""

import datetime
import logging
import sys
from typing import Any, Dict, List, Optional


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
    logger = logging.getLogger("reconnoiter")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid duplicate handlers if called multiple times
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


def print_banner(version: str = "2.0.0") -> None:
    """Prints a styled terminal banner."""
    banner = f"""{ColorCodes.CYAN}{ColorCodes.BOLD}
""" + r""" ____                                     _ _            
|  _ \ ___  ___ ___  _ __  _ __   ___ (_) |_ ___ _ __ 
| |_) / _ \/ __/ _ \| '_ \| '_ \ / _ \| | __/ _ \ '__|
|  _ <  __/ (_| (_) | | | | | | | (_) | | ||  __/ |   
|_| \_\___|\___\___/|_| |_|_| |_|\___/|_|\__\___|_|   """ + f"""
    {ColorCodes.YELLOW}Advanced Network Reconnaissance & Vulnerability Pipeline v{version}{ColorCodes.RESET}
"""
    print(banner)


def format_table(headers: List[str], rows: List[List[str]]) -> str:
    """Renders a clean text table for terminal output."""
    if not rows:
        return ""

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            if idx < len(col_widths):
                col_widths[idx] = max(col_widths[idx], len(str(cell)))

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    row_lines = [
        " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
        for row in rows
    ]

    return f"\n{header_line}\n{sep_line}\n" + "\n".join(row_lines) + "\n"
