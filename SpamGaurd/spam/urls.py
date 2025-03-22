from django.urls import path
from .views import(
    SearchByNameView,
    SearchByPhoneView,
    MarkSpamView,
     )
urlpatterns = [
    path('search/name/', SearchByNameView.as_view(), name='search-by-name'),
    path('search/phone/', SearchByPhoneView.as_view(), name='search-by-phone'),
    path('mark-spam/', MarkSpamView.as_view(), name='mark-spam'),
]