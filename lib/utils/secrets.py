import json
import os
from urllib.parse import quote_plus
import requests
from lib.utils.logs import create_logger

logger = create_logger(__name__)


def get_credentials(creds: str):
    """Get credentials from Secrets.cisco.com"""
    secret = Secret(url=os.getenv('SECRETS_URL'), project=os.getenv('SECRETS_PROJECT'), secret=creds,
                    token=os.getenv('SECRETS_TOKEN'))
    if not secret.get_secret():
        raise ValueError('Failed to retrieve secret')
    return secret.password


class Secret:
    def __init__(self, url: str, project: str, secret: str, token: str):
        self.secret = quote_plus(secret.encode('utf-8'))
        self.api_url = f'{url}/api/v1/{project}/secrets/variable/{self.secret}'
        self.token = token
        self.password = None

    def get_secret(self) -> str | None:
        r = requests.get(url=self.api_url, headers={"Authorization": self.token})
        if r.status_code == 200:
            logger.info(f'Secret {self.secret} retrieved successfully')
            self.password = r.json()["data"]
            return self.password
        else:
            logger.error(f'Secret {self.secret} retrieval failed')
            return None

    def set_secret(self) -> bool:
        data = {"data": self.password}
        r = requests.post(url=self.api_url, data=json.dumps(data), headers={"Authorization": self.token})
        if r.status_code == 200 or r.status_code == 201:
            logger.info(f'Secret {self.secret} set successfully')
            return True
        else:
            logger.error(f'Secret {self.secret} set failed')
            return False
