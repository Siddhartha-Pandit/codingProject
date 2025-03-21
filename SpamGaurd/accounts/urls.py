from django.urls import path
from .views import AuthTestView,UserRegistrationView,UserLoginView,GenerateOTPView,VerifyOTPView,ChangePasswordView,ResetPasswordOTPView
urlpatterns = [
    path('auth-test/',AuthTestView.as_view(),name="auth_test" ),
    path('register/',UserRegistrationView.as_view(),name="register" ),
    path('login/',UserLoginView.as_view(),name="login" ),
    path('generate-otp/', GenerateOTPView.as_view(), name='generate-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('reset-password/', ResetPasswordOTPView.as_view(), name='reset-password-otp'),
]
