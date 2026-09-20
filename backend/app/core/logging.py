import logging
import sys
from app.core.config import settings

def setup_logging() -> logging.Logger:
    """
    Configures structured, clean console logging for MAILSENTINEL.
    """
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    # Custom format with timestamp, level, module, message
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicate lines
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
        
    root_logger.addHandler(handler)

    # Set specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("mailsentinel").setLevel(log_level)

    logger = logging.getLogger("mailsentinel")
    logger.info(f"Initialized logging at level {settings.LOG_LEVEL} for {settings.PROJECT_NAME}")
    return logger

logger = logging.getLogger("mailsentinel")
