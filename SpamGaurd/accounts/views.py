from django.http import HttpResponse
from rest_framework import generics, permissions, status
import logging
from .serializers.serializers import UserSerializer
from .models import User
from .utils.ApiResponse import ApiResponse
from .utils.ApiError import ApiError
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from   .utils.otp import send_otp,verify_otp
from .serializers.PasswordSerializers import PasswordSerializer
from .serializers.ResetPasswordOTPSerializer import ResetPasswordOTPSerializer
from .utils.emailUtils import send_verification_email
from .serializers.EmailUpdateSerializer import EmailUpdateSerializer
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model


logger = logging.getLogger(__name__)
User = get_user_model()

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
    serializer_class = UserSerializer 
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


class GenerateOTPView(APIView):
    permissions_classes=[permissions.AllowAny]
    
    def post(self,request,*args,**kwargs):
        phone = request.data.get('phone')
        if not phone:
            apiError=ApiError(
                status_code=status.HTTP_400_BAD_REQUEST,
                message="Missing phone number",
                errors=["Phone number is required"]
            )
            return Response(apiError.to_dict(),status=status.HTTP_400_BAD_REQUEST)
        
        try:
            success,message=send_otp(phone)
            if success:
                logger.info(f"OTP is sent successfully to phone {phone}.")
                apiResponse=ApiResponse(
                    status_code=status.HTTP_200_OK,
                    data=None,
                    message="OTP is sent successfully"
                )
                return Response(apiResponse.to_dict(),status=status.HTTP_200_OK)
            else:
                logger.error(f"Failed to send the OTP to phone {phone}")
                apiError=ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message=message,
                    errors=[message]
                )
                return Response(apiError.to_dict(),status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"Error while sending OTP to phone {phone}: {str(e)}")
            apiError=ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                errors=[str(e)]
            )
            return Response(apiError.to_dict(),status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyOTPView(APIView):
    permission_classes=[permissions.AllowAny]
    def post(self, request, *args, **kwargs):
        phone=request.data.get('phone')
        otp=request.data.get('otp')
        if not (phone and otp):
            apiError=ApiError(
                status_code=status.HTTP_400_BAD_REQUEST,
                message="phone and OTP both are required",
                errors=["Phone number and OTP are required"]
            )
            return Response(apiError.to_dict(),status=status.HTTP_400_BAD_REQUEST)    

        try:
            verified,message=verify_otp(phone,otp)
            if verified:
                try:
                    user=User.objects.get(phone=phone)
                    user.is_active=True
                    user.save()
                    logger.info(f"User phone {phone} is verified successfully.")
                    apiResponse=ApiResponse(
                        status_code=status.HTTP_200_OK,
                        data=None,
                        message="OTP is verified successfully"
                    )
                    return Response(apiResponse.to_dict(),status=status.HTTP_200_OK)
            
                except User.DoesNotExist:
                    logger.error(f"User phone {phone} is not found")
                    apiError=ApiError(
                        status_code=status.HTTP_404_NOT_FOUND,
                        message="User not found",
                        errors=["User not found"]
                    )
                    return Response(apiError.to_dict(),status=status.HTTP_404_NOT_FOUND)
            else:
                logger.warning(f"OTP verification failed for phone {phone}")   
                apiError=ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message=message,
                    errors=[message]
                )
                return Response(apiError.to_dict(),status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"Error while verifying OTP for phone {phone}: {str(e)}")
            apiError=ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="internal server error.",
                errors=[str(e)]
            )
            return Response(apiError.to_dict(),status=status.HTTP_500_INTERNAL_SERVER_ERROR)
             
class ChangePasswordView(APIView):
    permission_classes=[permissions.IsAuthenticated]
    def put(self, request, *args, **kwargs):
        try:
            serializer = PasswordSerializer(data=request.data)
            if not serializer.is_valid():
                apiError = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Validation error.",
                    errors=serializer.errors
                )
                return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            user = request.user
            oldPassword = serializer.validated_data['oldPassword']
            if not user.check_password(oldPassword):
                apiError = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Old password is incorrect.",
                    errors=["Old password is incorrect."]
                )
                return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            newPassword = serializer.validated_data['newPassword']
            # The validate_newPassword method in the serializer already checks password strength.
            user.set_password(newPassword)
            user.save()
            logger.info(f"User {user.pk} changed their password successfully.")
            apiResponse = ApiResponse(
                status_code=status.HTTP_200_OK,
                data={"message": "Password changed successfully."},
                message="Password changed successfully."
            )
            return Response(apiResponse.to_dict(), status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(f"Error while changing password for user {request.user.pk}: {str(e)}")
            apiError = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Internal server error.",
                errors=[str(e)]
            )
            return Response(apiError.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ResetPasswordOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def put(self, request, *args, **kwargs):
        try:
            serializer = ResetPasswordOTPSerializer(data=request.data)
            if not serializer.is_valid():
                apiError = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Validation error.",
                    errors=serializer.errors
                )
                return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            phone = serializer.validated_data['phone']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['newPassword']

            # Verify OTP using the OTP utility (which uses Redis)
            verified, msg = verify_otp(phone, otp)
            if not verified:
                apiError = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message=msg,
                    errors=[msg]
                )
                return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(phone=phone)
            except User.DoesNotExist:
                apiError = ApiError(
                    status_code=status.HTTP_404_NOT_FOUND,
                    message="User with provided phone not found.",
                    errors=["User with provided phone not found."]
                )
                return Response(apiError.to_dict(), status=status.HTTP_404_NOT_FOUND)

            user.set_password(new_password)
            user.save()
            logger.info(f"Password reset successfully for user with phone {phone}.")
            apiResponse = ApiResponse(
                status_code=status.HTTP_200_OK,
                data={"phone": phone},
                message="Password reset successfully."
            )
            return Response(apiResponse.to_dict(), status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(f"Error while resetting password for phone {request.data.get('phone')}: {str(e)}")
            apiError = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Internal server error.",
                errors=[str(e)]
            )
            return Response(apiError.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)  
        

class AddEmailView(APIView):
   
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = EmailUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            apiError = ApiError(
                status_code=status.HTTP_400_BAD_REQUEST,
                message="Validation error.",
                errors=serializer.errors
            )
            return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        user = request.user
        user.email = email
        user.is_email_verified = False
        user.save()

        # Generate token and UID for email verification.
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_link = request.build_absolute_uri(f"/api/v1/auth/verify-email/?uid={uid}&token={token}")

        subject = "Verify Your Email Address"
        message = (
            f"Hi {user.name},\n\n"
            "Please verify your email address by clicking the link below:\n"
            f"{verification_link}\n\n"
            "If you did not request this change, please contact support."
        )
        
        try:
            send_verification_email(email, subject, message)
            logger.info(f"Verification email sent to {email} for user {user.pk}.")
            apiResponse = ApiResponse(
                status_code=status.HTTP_200_OK,
                data={"message": "Verification email sent successfully."},
                message="Verification email sent successfully."
            )
            return Response(apiResponse.to_dict(), status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(f"Error sending verification email to {email} for user {user.pk}: {str(e)}")
            apiError = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Failed to send verification email.",
                errors=[str(e)]
            )
            return Response(apiError.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        uid64 = request.query_params.get('uid')
        token = request.query_params.get('token')

        if not uid64 or not token:
            logger.error("Missing uid or token in the request.")
            apiError = ApiError(
                status_code=status.HTTP_400_BAD_REQUEST,
                message="Missing uid or token.",
                errors=["Missing uid or token."]
            )
            return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = urlsafe_base64_decode(uid64).decode()
            user = User.objects.get(pk=uid)
        except Exception as e:
            logger.exception(f"Error decoding UID or fetching user: {str(e)}")
            apiError = ApiError(
                status_code=status.HTTP_400_BAD_REQUEST,
                message="Invalid UID.",
                errors=["Invalid UID."]
            )
            return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            user.is_email_verified = True
            user.save()
            logger.info(f"User {user.pk} email verified successfully.")
            apiResponse = ApiResponse(
                status_code=status.HTTP_200_OK,
                data={"message": "Email verified successfully."},
                message="Email verified successfully."
            )
            return Response(apiResponse.to_dict(), status=status.HTTP_200_OK)
        else:
            logger.warning(f"Invalid or expired token for user {user.pk}.")
            apiError = ApiError(
                status_code=status.HTTP_400_BAD_REQUEST,
                message="Invalid token or expired.",
                errors=["Invalid token or expired."]
            )
            return Response(apiError.to_dict(), status=status.HTTP_400_BAD_REQUEST)