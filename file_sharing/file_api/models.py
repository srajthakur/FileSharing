from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

class CustomUser(AbstractUser):
    is_verified = models.BooleanField(default=False)
    USER_TYPE_CHOICES = (
        ('OPS', 'Operation User'),
        ('CLIENT', 'Client User'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)



class File(models.Model):
    uploaded_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    allowed_types = [
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # docx
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',  # pptx
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'  # xlsx
    ]
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.file.file.content_type not in self.allowed_types:
            raise ValueError("Invalid file type")
        super().save(*args, **kwargs)


class BlacklistedToken(models.Model):
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.token