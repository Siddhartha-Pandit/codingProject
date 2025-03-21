import traceback

class ApiError(Exception):
    def __init__(self, status_code, message="Something went wrong", errors=None, stack=None):
        super().__init__(message)
        self.status_code = status_code
        self.data = None
        self.message = message
        self.success = False
        self.errors = errors if errors is not None else []
        # Capture stack trace if not provided
        self.stack = stack if stack else traceback.format_exc()

    def to_dict(self):
        return {
            "statusCode": self.status_code,
            "data": self.data,
            "message": self.message,
            "success": self.success,
            "errors": self.errors,
            "stack": self.stack,
        }
