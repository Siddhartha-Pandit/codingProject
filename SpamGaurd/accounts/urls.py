from django.urls import path
from .views import AuthTestView,UserRegistrationView,UserLoginView
urlpatterns = [
    path('auth-test/',AuthTestView.as_view(),name="auth_test" ),
    path('register/',UserRegistrationView.as_view(),name="register" ),
    path('login/',UserLoginView.as_view(),name="login" ),
]
