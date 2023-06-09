from .fsm_parser import fsm_parser
import pathlib
import io

TEMPLATE_DIR = pathlib.Path(__file__).parent

with open(f"{TEMPLATE_DIR}/mds_show_interface_fc.textfsm", 'r') as f:
    fsm_template_mds_show_interface_fc = io.StringIO(f.read())
    f.close()

with open(f"{TEMPLATE_DIR}/mds_show_interface_mgmt.textfsm", 'r') as f:
    fsm_template_mds_show_interface_mgmt = io.StringIO(f.read())
    f.close()