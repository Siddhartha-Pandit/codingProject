from django.urls import path
from .views import(
     AuthTestView,
    
     )
urlpatterns = [
    path('auth-test/',AuthTestView.as_view(),name="auth_test" ),
   
]