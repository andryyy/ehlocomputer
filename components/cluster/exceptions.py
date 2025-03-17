from werkzeug.exceptions import HTTPException


class DistLockCancelled(Exception):
    pass


class IncompleteClusterResponses(Exception):
    pass


class ZombiePeer(Exception):
    pass


class UnknownPeer(Exception):
    pass


class ClusterHTTPException(HTTPException):
    def __init__(self, description=None):
        super().__init__(description)
        self.code = 999
