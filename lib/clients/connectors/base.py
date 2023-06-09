import abc


class BaseDeviceHandler(abc.ABC):

    def __init__(self, ip: str, credentials: dict):
        self.ip = ip
        self.credentials = credentials
        self.username = credentials['default']['username']
        self.password = credentials['default']['password']
        self.handler = None

    @abc.abstractmethod
    def connect(self):
        pass

    @abc.abstractmethod
    def disconnect(self):
        pass

    @abc.abstractmethod
    def execute(self, command: str) -> str:
        pass

    @abc.abstractmethod
    def discover(self) -> dict:
        pass
