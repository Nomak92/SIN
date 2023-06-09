import logging
import subprocess

logger = logging.getLogger()


def get_credentials(creds: str):
    """Get credentials from gopass."""
    logger.debug(f'Getting credentials for {creds}')
    return subprocess.check_output(['gopass', 'show', '-o', creds]).decode('utf-8')
