"""Public errors, with stable machine-readable codes."""


class Error(Exception):
    def __init__(self, code: str, message: str, status: int = 409):
        super().__init__(message)
        self.code = code
        self.status = status

    def as_dict(self):
        return {"error": {"code": self.code, "message": str(self)}}
