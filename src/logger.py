import logging
import sys



def get_logger(name: str) -> logging.Logger:
    """Creates a standardized logger that outputs to stdout for Docker compatibility."""
    logger = logging.getLogger(name)
    
    # Prevent duplicate logs if the logger is initialized multiple times
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Create a clean, readable format
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(levelname)s - [%(name)s:%(lineno)d] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # Stream directly to stdout so Docker can capture it instantly
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger
