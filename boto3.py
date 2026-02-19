
# Dummy boto3 for verification
class Session:
    def __init__(self, *args, **kwargs):
        pass
    def client(self, *args, **kwargs):
        return MagicMock()
    def resource(self, *args, **kwargs):
        return MagicMock()

def client(*args, **kwargs):
    return MagicMock()

def resource(*args, **kwargs):
    return MagicMock()

from unittest.mock import MagicMock
