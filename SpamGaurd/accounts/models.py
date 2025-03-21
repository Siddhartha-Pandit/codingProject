from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self,name,phone,password=None,email=None,**extra_fields):
        if not phone:
            raise ValueError("Phone number is required for registration")
        if not phone.startswith('+'):
            raise ValueError("Complete phone number with country code is required (e.g., '+1...')")
        if email:
            email=self.normalize_email(email)   
        else:
            email=None
        user=self.model(name=name, phone=phone, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self,name,phone,password,email=None,**extra_fields):
        user=self.create_user(name,phone,password,email,**extra_fields)
        user.is_admin=True
        user.is_staff=True
        user.is_superuser=True
        user.save(using=self._db)
        return user
class User(AbstractBaseUser,PermissionsMixin):
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15,unique=True)
    email = models.EmailField(max_length=255,unique=False,null=True,blank=True)
    is_active = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)  
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['name']
    objects = UserManager()

    def __str__(self):
        return self.name