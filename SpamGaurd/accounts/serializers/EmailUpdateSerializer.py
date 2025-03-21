from rest_framework import serializers

class EmailUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
