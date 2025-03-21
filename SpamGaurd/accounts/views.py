from django.shortcuts import render
from rest_framework.views import APIView
from django.http import HttpResponse

class AuthTestView(APIView):
    def get(self, request,*args, **kwargs):
        return  HttpResponse("Hello, authenticated user!", content_type="text/plain")

