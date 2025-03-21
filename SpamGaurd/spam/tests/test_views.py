from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from accounts.models import User
from spam.models import SpamReport, Contact

class SpamViewsTests(APITestCase):
    def setUp(self):
        # Create test user and authenticate
        self.user = User.objects.create_user(
            name="TestUser",
            phone="+1234567890",
            password="Testpass1!"
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        # Create additional test data
        self.other_user = User.objects.create_user(
            name="OtherUser",
            phone="+10987654321",
            password="Otherpass1!"
        )
        self.contact = Contact.objects.create(
            user=self.user,
            name="ContactUser",
            phone="+15555555555"
        )

    def test_auth_test_view(self):
        """Test authenticated endpoint returns correct response"""
        url = reverse('auth_test')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "Hello, authenticated user!")

    def test_search_by_name_view_missing_query(self):
        """Test search by name returns 400 when missing query parameter"""
        url = reverse('search-by-name')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Query parameter is required", response.data.get('message', ''))

    def test_search_by_name_view_success(self):
        """Test successful name search with results"""
        url = reverse('search-by-name')
        response = self.client.get(url, {'q': 'user'})  # Should match TestUser and OtherUser
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 2)

    def test_mark_spam_view_self_report(self):
        """Test user can't mark their own number as spam"""
        url = reverse('mark-spam')
        response = self.client.post(url, {'phone': self.user.phone})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Cannot report your own number", response.data.get('message', ''))

    def test_mark_spam_view_success(self):
        """Test successful spam reporting"""
        url = reverse('mark-spam')
        test_phone = "+19876543210"
        
        # First report (should create)
        response = self.client.post(url, {'phone': test_phone})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Duplicate report (should update)
        response = self.client.post(url, {'phone': test_phone})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify spam count
        spam_count = SpamReport.objects.filter(phone=test_phone).count()
        self.assertEqual(spam_count, 1)  # Should still be 1 due to get_or_create

    def test_search_by_phone_view_found_user(self):
        """Test phone search returns user when exists"""
        url = reverse('search-by-phone')
        response = self.client.get(url, {'q': self.other_user.phone})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]['type'], 'user')
        self.assertEqual(response.data[0]['name'], self.other_user.name)

    def test_search_by_phone_view_found_contact(self):
        """Test phone search returns contact when exists"""
        url = reverse('search-by-phone')
        response = self.client.get(url, {'q': self.contact.phone})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]['type'], 'contact')
        self.assertEqual(response.data[0]['name'], self.contact.name)

    def test_search_by_phone_view_not_found(self):
        """Test phone search returns 404 for unknown numbers"""
        url = reverse('search-by-phone')
        response = self.client.get(url, {'q': '+19999999999'})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)