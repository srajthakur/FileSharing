from django.contrib import admin

# admin.py
from django.contrib import admin
from .models import CustomUser,File

# Register the Post model
admin.site.register(CustomUser)
admin.site.register(File)