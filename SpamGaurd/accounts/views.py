from django.http import HttpResponse
from rest_framework import generics, permissions, status
import logging
from .serializers import UserSerializer
from .models import User
from accounts.utils.ApiResponse import ApiResponse
from accounts.utils.ApiError import ApiError
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)

class AuthTestView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return HttpResponse("Hello, authenticated user!", content_type="text/plain")


class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                refresh = RefreshToken.for_user(user)
                logger.info(f"User created successfully with phone number {user.phone}")
                responseData = {
                    "user": UserSerializer(user).data,
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh)
                }
                apiResponse = ApiResponse(
                    status_code=status.HTTP_201_CREATED,
                    data=responseData,
                    message="User created successfully"
                )
                return Response(apiResponse.to_dict(), status=status.HTTP_201_CREATED)
            else:
                apiError = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Validation Error",
                    errors=serializer.errors
                )
                return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error while registering user: {str(e)}")
            apiError = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                errors=[str(e)]
            )
            return Response(apiError.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLoginView(generics.GenericAPIView):
    serializer_class = UserSerializer  # Optionally, you may use a dedicated login serializer.
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            countryCode = request.data.get('countryCode')
            phoneNumber = request.data.get('phoneNumber')
            password = request.data.get('password')
            if not (countryCode and phoneNumber and password):
                apiError = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Missing credentials",
                    errors=["countryCode, phoneNumber, and password are required."]
                )
                return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)
            
            phone = f"{countryCode}{phoneNumber}"
            user = authenticate(phone=phone, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                logger.info(f"User logged in successfully with phone number {user.phone}")
                responseData = {
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh)
                }
                apiResponse = ApiResponse(
                    status_code=status.HTTP_200_OK,
                    data=responseData,
                    message="User logged in successfully"
                )
                return Response(apiResponse.to_dict(), status=status.HTTP_200_OK)
            else:
                apiError = ApiError(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    message="Invalid credentials",
                    errors=["Invalid phone or password"]
                )
                return Response(apiError.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"Error while logging in user: {str(e)}")
            apiError = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                errors=[str(e)]
            )
            return Response(apiError.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
