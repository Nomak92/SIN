import textfsm
from lib.utils.logs import create_logger

logger = create_logger(__name__)


def fsm_parser(raw_text, fsm_template):
    logger.debug(f'textfsm parsing data:\n{raw_text}')
    fsm = textfsm.TextFSM(fsm_template)
    parse_result = fsm.ParseText(raw_text)
    fsm_result = []
    for result in parse_result:
        fsm_result.append(dict(zip(fsm.header, result)))
    logger.debug(f'textfsm parsing completed. Results:\n{fsm_result}')
    return fsm_result
