"""领域错误。服务层抛出带错误码的异常，HTTP 层统一映射为 JSON。"""


class DomainError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class NotFound(DomainError):
    def __init__(self, what: str):
        super().__init__("not_found", f"{what} 不存在", 404)


class Conflict(DomainError):
    def __init__(self, code: str, message: str):
        super().__init__(code, message, 409)


class ValidationFailed(DomainError):
    def __init__(self, message: str):
        super().__init__("validation_failed", message, 422)


class Forbidden(DomainError):
    def __init__(self, message: str):
        super().__init__("forbidden", message, 403)
