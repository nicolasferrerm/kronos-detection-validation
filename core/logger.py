# core/logger.py
import logging
import sys


# ANSI Colors for terminal output
class Colors:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class KronosFormatter(logging.Formatter):
    """Custom formatter to style logs based on level."""

    def format(self, record):
        level = record.levelname
        msg = record.getMessage()

        if level == "INFO":
            prefix = f"{Colors.BLUE}[*]{Colors.RESET} "
        elif level == "WARNING":
            prefix = f"{Colors.YELLOW}[!]{Colors.RESET} "
        elif level == "ERROR":
            prefix = f"{Colors.RED}[-]{Colors.RESET} "
        elif level == "CRITICAL":
            prefix = f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.RESET} "
        elif level == "SUCCESS":
            prefix = f"{Colors.GREEN}[+]{Colors.RESET} "
        else:
            prefix = "[ ] "

        return f"{prefix}{msg}"


# Add custom SUCCESS log level
SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")


def success(self, message, *args, **kws):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kws)


logging.Logger.success = success


def setup_logger(name="KRONOS", level=logging.INFO):
    """Sets up a colored console logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(KronosFormatter())
        logger.addHandler(console_handler)

    return logger


# Global logger instance
logger = setup_logger()
