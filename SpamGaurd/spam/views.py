import logging
from django.db.models import Count
from django.http import HttpResponse  # Not used anymore for API responses
from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.postgres.search import SearchVector, SearchQuery, SearchRank

from .models import Contact, SpamReport
from accounts.models import User
from utils.ApiResponse import ApiResponse
from utils.ApiError import ApiError

logger = logging.getLogger(__name__)

class AuthTestView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Wrap plain text message in an ApiResponse
        api_response = ApiResponse(
            status_code=status.HTTP_200_OK,
            data="Hello, authenticated user!",
            message="Success"
        )
        return Response(api_response.to_dict(), status=status.HTTP_200_OK)

class SearchByNameView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            query = request.query_params.get('q', '').strip().lower()
            if not query:
                api_error = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Query parameter is required"
                )
                return Response(api_error.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            spam_counts = dict(
                SpamReport.objects.filter(user=request.user)
                .values_list('phone')
                .annotate(count=Count('phone'))
            )

            # Use full-text search if using PostgreSQL
            if 'postgres' in str(User.objects.db):
                user_queryset = User.objects.annotate(
                    rank=SearchRank(SearchVector('name'), SearchQuery(query))
                ).filter(rank__gt=0.1).order_by('-rank')
            else:
                user_queryset = User.objects.filter(name__icontains=query)

            contact_queryset = Contact.objects.filter(
                user=request.user, 
                name__icontains=query
            )

            def process_results(queryset, is_user=True):
                return [{
                    'name': item.name,
                    'phone': item.phone,
                    'spam_likelihood': spam_counts.get(item.phone, 0),
                    'type': 'user' if is_user else 'contact'
                } for item in queryset]

            results = process_results(user_queryset) + process_results(contact_queryset, False)
            seen = set()
            # Deduplicate results based on (phone, type)
            unique_results = [r for r in results if not (r['phone'], r['type']) in seen and not seen.add((r['phone'], r['type']))]

            api_response = ApiResponse(
                status_code=status.HTTP_200_OK,
                data=unique_results,
                message="Search results retrieved successfully"
            )
            return Response(api_response.to_dict(), status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("SearchByNameView error")
            api_error = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message=f"An error occurred: {str(e)}"
            )
            return Response(api_error.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SearchByPhoneView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            query = request.query_params.get('q', '').strip()
            if not query:
                api_error = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Phone number required"
                )
                return Response(api_error.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            spam_count = SpamReport.objects.filter(phone=query).count()
            user = User.objects.filter(phone=query).first()
            
            if user:
                api_response = ApiResponse(
                    status_code=status.HTTP_200_OK,
                    data=[{
                        'name': user.name,
                        'phone': user.phone,
                        'spam_likelihood': spam_count,
                        'type': 'user'
                    }],
                    message="User found"
                )
                return Response(api_response.to_dict(), status=status.HTTP_200_OK)

            contacts = Contact.objects.filter(phone=query).values('name').distinct()
            results = [{
                'name': c['name'],
                'phone': query,
                'spam_likelihood': spam_count,
                'type': 'contact'
            } for c in contacts]

            if results:
                api_response = ApiResponse(
                    status_code=status.HTTP_200_OK,
                    data=results,
                    message="Contacts found"
                )
                return Response(api_response.to_dict(), status=status.HTTP_200_OK)
            else:
                api_error = ApiError(
                    status_code=status.HTTP_404_NOT_FOUND,
                    message="No results found"
                )
                return Response(api_error.to_dict(), status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.exception("SearchByPhoneView error")
            api_error = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message=f"An error occurred: {str(e)}"
            )
            return Response(api_error.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MarkSpamView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            phone = request.data.get('phone', '').strip()
            if not phone:
                api_error = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Phone number required"
                )
                return Response(api_error.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            if phone == request.user.phone:
                api_error = ApiError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Cannot report your own number"
                )
                return Response(api_error.to_dict(), status=status.HTTP_400_BAD_REQUEST)

            _, created = SpamReport.objects.get_or_create(
                user=request.user,
                phone=phone
            )
            api_response = ApiResponse(
                status_code=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
                data={"message": "Number marked as spam"},
                message="Number marked as spam"
            )
            return Response(api_response.to_dict(), status=(status.HTTP_201_CREATED if created else status.HTTP_200_OK))

        except Exception as e:
            logger.exception("MarkSpamView error")
            api_error = ApiError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message=f"An error occurred: {str(e)}"
            )
            return Response(api_error.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
