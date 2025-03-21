class ApiResponse:
    def __init__(self, status_code, data, message="Success"):
        self.status_code = status_code
        self.data = data
        self.message = message
        self.success = status_code < 400

    def to_dict(self):
        return {
            "statusCode": self.status_code,
            "data": self.data,
            "message": self.message,
            "success": self.success,
        }
