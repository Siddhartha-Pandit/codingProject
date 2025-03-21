from django.urls import path
from .views import(
    AuthTestView,
    SearchByNameView,
    SearchByPhoneView,
    MarkSpamView,
     )
urlpatterns = [
    path('auth-test/',AuthTestView.as_view(),name="auth_test" ),
    path('search/name/', SearchByNameView.as_view(), name='search-by-name'),
    path('search/phone/', SearchByPhoneView.as_view(), name='search-by-phone'),
    path('mark-spam/', MarkSpamView.as_view(), name='mark-spam'),
]