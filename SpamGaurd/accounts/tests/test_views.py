from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from accounts.models import User

class AccountsViewsTests(APITestCase):

    def setUp(self):
        self.client = APIClient()

    def test_user_registration_success(self):
      
        url = reverse('register')  
        data = {
            "name": "NewUser",
            "country_code": "+1",      
            "phone_number": "0123456789", 
            "password": "Testpassword1!", 
            "confirm_password": "Testpassword1!", 
            "email": "newuser@example.com"
        }
        response = self.client.post(url, data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print("Registration error details:", response.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("User created successfully", response.data.get('message', ''))

    def test_user_login_invalid_credentials(self):
       
        User.objects.create_user(
            name="TestUser",
            phone="+10234567890",
            password="correctpassword"
        )
        url = reverse('login')
        data = {
            "countryCode": "+1",
            "phoneNumber": "0234567890", 
            "password": "wrongpassword"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("Invalid credentials", response.data.get('message', ''))

    def test_generate_otp_missing_phone(self):
     
        url = reverse('generate-otp') 
        data = {} 
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Missing phone number", response.data.get('message', ''))
