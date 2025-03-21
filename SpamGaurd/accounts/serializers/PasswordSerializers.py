import re
from rest_framework import serializers

class PasswordSerializer(serializers.Serializer):
    oldPassword = serializers.CharField(required=True)
    newPassword = serializers.CharField(required=True)
    confirmPassword = serializers.CharField(required=True)

    def validate_newPassword(self, value):
        """
        Validate that the new password meets the strength requirements.
        Regex requirements:
          - At least 8 characters
          - Contains at least one uppercase letter
          - Contains at least one lowercase letter
          - Contains at least one digit
          - Contains at least one special character (@$!%*?&)
        """
        regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(regex, value):
            raise serializers.ValidationError(
                "Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one digit, and one special character."
            )
        return value

    def validate(self, data):
        if data["newPassword"] != data["confirmPassword"]:
            raise serializers.ValidationError("New password and confirm password do not match.")
        return data
