from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    country_code = serializers.CharField(write_only=True)
    phone_number = serializers.CharField(write_only=True)
    phone = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'country_code', 'phone_number', 'phone', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        country_code = validated_data.pop('country_code')
        phone_number = validated_data.pop('phone_number')
        full_phone = f"{country_code}{phone_number}"
        validated_data['phone'] = full_phone

        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        country_code = validated_data.pop('country_code', None)
        phone_number = validated_data.pop('phone_number', None)
        if country_code and phone_number:
            instance.phone = f"{country_code}{phone_number}"
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        instance.save()
        return instance
