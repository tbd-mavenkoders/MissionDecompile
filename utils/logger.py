"""
Logging utilities for the preprocessing pipeline.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logger(name: str, log_dir: str = None, level=logging.INFO):
  """
  Set up a logger with both file and console handlers.
  
  Args:
      name: Logger name
      log_dir: Directory to save log files
      level: Logging level
  
  Returns:
      Logger instance
  """
  logger = logging.getLogger(name)
  logger.setLevel(level)
  
  # Avoid duplicate handlers
  if logger.handlers:
    return logger
  
  # Create formatters
  detailed_formatter = logging.Formatter(
      '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
      datefmt='%Y-%m-%d %H:%M:%S'
  )
  simple_formatter = logging.Formatter(
      '%(levelname)s - %(message)s'
  )
  
  # Console handler
  console_handler = logging.StreamHandler(sys.stdout)
  console_handler.setLevel(logging.INFO)
  console_handler.setFormatter(simple_formatter)
  logger.addHandler(console_handler)
  
  # File handler (if log_dir provided)
  if log_dir:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = log_path / f"{name}_{timestamp}.log"
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)
  
  return logger
