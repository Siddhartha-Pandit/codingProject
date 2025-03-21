import random
import string
from django.core.management.base import BaseCommand
from accounts.models import User
from spam.models import Contact, SpamReport

def random_phone():
    return f"+1{random.randint(1000000000, 9999999999)}"

def random_name():
    return ''.join(random.choices(string.ascii_letters, k=7))

def populate_data(num_users=50, contacts_per_user=5):
    users = []
    # Create users
    for _ in range(num_users):
        name = random_name()
        phone = random_phone()
        if User.objects.filter(phone=phone).exists():
            continue  # ensure uniqueness
        user = User.objects.create_user(
            name=name,
            phone=phone,
            password="password123",
            email=f"{name.lower()}@example.com"
        )
        users.append(user)
    
    # Create contacts for each user
    for user in users:
        for _ in range(contacts_per_user):
            contact_name = random_name()
            # For some overlap, randomly pick a phone from the created users
            contact_phone = random.choice(users).phone
            # Use get_or_create to avoid duplicates due to unique constraint on (user, phone)
            Contact.objects.get_or_create(
                user=user,
                phone=contact_phone,
                defaults={'name': contact_name}
            )
    
    # Create random spam reports
    for _ in range(100):
        reporter = random.choice(users)
        spam_phone = random_phone()
        SpamReport.objects.get_or_create(user=reporter, phone=spam_phone)

class Command(BaseCommand):
    help = 'Populate the database with sample data.'

    def handle(self, *args, **options):
        populate_data()
        self.stdout.write(self.style.SUCCESS("Database populated with sample data."))
