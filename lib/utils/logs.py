"""Define logging parameters for application"""

import logging
# Logging variables
# Name of log file
import pathlib
from logging.handlers import QueueHandler
from multiprocessing import Queue

log_file = pathlib.Path(__file__).parent.parent.parent.joinpath("logs/app.log")
# encoding
log_encode = 'utf-8'
# logging level
log_level = logging.DEBUG
# logging format
log_format = "%(processName)s - %(threadName)s - %(asctime)s - %(levelname)s - %(message)s"
# date format
log_date = "%m/%d/%Y %I:%M:%S %p"


# Create logger function
def create_logger(modname=None) -> logging.Logger:
    """
    :param modname: Specify module name for new logger creation (Default: None - returns root logger)
    :return: :py:func:`logging.getLogger`
    """
    global log_file
    global log_encode
    global log_format
    global log_date
    logger_handler = logging.getLogger(modname)
    logger_handler.setLevel(log_level)
    logging_console = logging.StreamHandler()
    logging_console.setLevel(log_level)
    logging_file = logging.FileHandler(log_file)
    logging_file.setLevel(log_level)
    log_formatter = logging.Formatter(log_format)
    logging_console.setFormatter(log_formatter)
    logging_file.setFormatter(log_formatter)
    logger_handler.addHandler(logging_console)
    logger_handler.addHandler(logging_file)
    return logger_handler


def create_logger_process(logger_queue: Queue, logger: logging.Logger):
    handler = QueueHandler(logger_queue)
    logger.addHandler(handler)
    while True:
        message = logger_queue.get()
        if message is None:
            break
        logger.handle(message)

