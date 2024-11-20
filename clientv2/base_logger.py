import logging
from colorlog import ColoredFormatter

__log_format = (
    '%(asctime)s '
    '%(log_color)s'
    '%(levelname)-8s'
    '%(reset)s '
    '%(message)s'
)

__formatter = ColoredFormatter(
    __log_format,
    datefmt='%Y-%m-%d %H:%M:%S',
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    }
)

__handler = logging.StreamHandler()
__handler.setFormatter(__formatter)

global base_logger
base_logger = logging.getLogger(__name__)
base_logger.setLevel(logging.DEBUG)
base_logger.addHandler(__handler)