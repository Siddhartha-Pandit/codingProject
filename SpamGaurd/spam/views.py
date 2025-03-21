from rest_framework import generics, permissions, status
from django.http import HttpResponse
# Create your views here.
class AuthTestView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return HttpResponse("Hello, authenticated user!", content_type="text/plain")

