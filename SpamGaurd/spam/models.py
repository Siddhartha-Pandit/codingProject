from django.db import models
from accounts.models import User

class Contact(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='contacts')
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        unique_together = ('user', 'phone')
    def __str__(self):
        return self.name

class SpamReport(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='spam_reports')
    phone = models.CharField(max_length=15)
    reported_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ('user', 'phone')
    def __str__(self):
        return self.phone