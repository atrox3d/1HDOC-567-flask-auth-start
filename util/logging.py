import sys
import logging
import functools
import util.params

logger = logging.getLogger(__name__)

##################################################################################################################
# logging.NOTSET | "NOTSET" | 0:
#       Detailed information, typically of interest only when diagnosing problems.
# logging.DEBUG | "DEBUG" | 10:
#       Detailed information, typically of interest only when diagnosing problems.
# logging.INFO | "INFO" | 20:
#       Confirmation that things are working as expected.
# logging.WARNING | "WARNING" | 30:
#       An indication that something unexpected happened, or indicative of some problem in the near future
#       (e.g. ‘disk space low’). The software is still working as expected.
# logging.ERROR | "ERROR" | 40:
#       Due to a more serious problem, the software has not been able to perform some function.
# logging.CRITICAL | "CRITICAL" | 50:
#       A serious error, indicating that the program itself may be unable to continue running.
##################################################################################################################
FORMAT_STRING = '%(asctime)s | %(levelname)-8s | %(name)20s | %(funcName)15s() | %(message)s'
ROOTLOGGER = None


def get_root_logger(format_string=FORMAT_STRING, level=logging.NOTSET) -> logging.Logger:
    """
    invokes basicConfig with format_string and level params

    returns rootlogger

    :param format_string: '%(asctime)s | %(levelname)-8s | %(name)-25s | %(funcName)20s() | %(message)s'
    :param level: logging.NOTSET
    :return: rootlogger
    """
    global ROOTLOGGER
    if not ROOTLOGGER:
        logging.basicConfig(level=level, format=format_string, stream=sys.stdout)
        logger.info("root logger configured.")
        ROOTLOGGER = logging.getLogger()
    return ROOTLOGGER


def get_cli_logger(
        name=None,  # root logger by default
        level=logging.DEBUG,
        set_handler=True,
        format_string=FORMAT_STRING,
        output_stream=sys.stderr,
) -> logging.Logger:
    """
    DEPRECATED
    
    creates a new logger with default attributes

    :param name: None
    :param level: logging.DEBUG
    :param set_handler: True
    :param format_string: '%(asctime)s | %(levelname)-8s | %(name)-25s | %(funcName)20s() | %(message)s'
    :param output_stream: stderr
    :return: logger
    """
    ############################################################################
    #    - GET LOCAL (NON-ROOT) LOGGER INSTANCE THAT OUTPUTS TO CLI
    #    - SET LEVEL TO DEBUG (DEFAULT IS WARNING)
    ############################################################################
    _logger = logging.getLogger(name)  # get local logger
    _logger.setLevel(level)  # set logger level >= logger_level
    ############################################################################
    #    - GET SAME FORMATTER INSTANCE FOR ALL HANDLERS
    ############################################################################
    format_string = format_string
    formatter = logging.Formatter(format_string)  # get formatter
    ############################################################################
    #    - GET CLI HANDLER INSTANCE
    #    - SET FORMATTER FOR CLI HANDLER INSTANCE
    #    - ADD HANDLER TO LOCAL LOGGER
    ############################################################################
    if set_handler and not _logger.hasHandlers():
        if isinstance(output_stream, str):
            # by stream name
            try:
                output_stream = {stream.name.strip("<>"): stream for stream in (sys.stderr, sys.stdout)}[output_stream]
                logger.debug(f"assigning {output_stream.name} to handler")
            except KeyError as ke:
                print(f"stream '{output_stream}' not found, setting sys.stderr")
                output_stream = sys.stderr
        elif not isinstance(output_stream, type(sys.stderr)):
            # by stream
            print(f"{output_stream} is not a {type(sys.stderr)}")
            output_stream = sys.stderr

        cli_handler = logging.StreamHandler(stream=output_stream)  # get CLI handler (default=stderr)
        cli_handler.setFormatter(formatter)  # set formatter for CLI handler
        _logger.addHandler(cli_handler)  # add CLI handler to logger

    return _logger


def list_loggers(attribute_name=None, attribute_value=None):
    """
    return a list of current loggers
    
    if attribute_name and attribute_value are specified,
    the list is filtered via gerattr
    
    :param attribute_name: 
    :param attribute_value: 
    :return: [loggers]
    """
    loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
    if attribute_name:
        loggers = [_logger for _logger in loggers if getattr(_logger, attribute_name) == attribute_value]
    return loggers


def list_logger_names():
    """
    :return: [logger names]
    """
    # logger_names = [logging.getLogger(name).name for name in logging.root.manager.loggerDict[:]]
    logger_names = [logger.name for logger in list_loggers()]
    return logger_names


def disable_loggers(*prefixes):
    """
    disable all loggers whose name starts with one of the prefixes

    :param prefixes: list of prefixes
    :return: None
    """
    for prefix in prefixes:
        for current_logger in list_loggers():
            if current_logger.name.startswith(prefix):
                logger.debug(f"disabling {current_logger.name}")
                current_logger.disabled = True


def list_disabled_loggers():
    return list_loggers("disabled", True)


def list_enabled_loggers():
    return list_loggers("disabled", False)


def log_formatdata(name, value):
    ret = []
    description = f"{name} <{type(value).__name__}>"
    if isinstance(value, tuple):
        ret.append(f"{description}: (")
        for item in value:
            ret.append(f"    {item}")
        ret.append(")")
    if isinstance(value, list):
        ret.append(f"{description}: [")
        for item in value:
            ret.append(f"    {item}")
        ret.append("]")
    elif isinstance(value, dict):
        ret.append(f"{description}: {{")
        for k, v in value.items():
            ret.append(f"    {k}: {v}")
        ret.append("}")
    elif isinstance(value, str):
        ret.append(f"{description}:")
        ret.extend(value.split('\n'))
    else:
        ret = [f"{description}: {value}"]
    return ret


def log_decorator(multiple_lines=False):
    def make_decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            logger.info(f"calling {fn.__name__}({util.params.params2str(*args, **kwargs)})")
            retval = fn(*args, **kwargs)
            # logger.info(f"return value:")
            for line in log_formatdata("return value", retval):
                logger.info(line)
                if not multiple_lines:
                    break
            return retval

        return wrapper

    return make_decorator


if __name__ == "__main__":
    pass
