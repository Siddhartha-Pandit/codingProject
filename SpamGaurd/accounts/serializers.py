from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['id', 'name', 'phone', 'email','password']
        read_only_fields = ['id']
       
    def create(self, validated_data):
        password=validated_data.pop('password')
        user=User(**validated_data)
        user.set_password(password)
        user.save()
        return user
    
    def update(self,instance,validate_data):
        password=validate_data.pop('password',None)
        for attr,value in validate_data.items():
           setattr(instance,attr,value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance