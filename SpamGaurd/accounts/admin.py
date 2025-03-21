from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

# class CustomUserAdmin(UserAdmin):
#     list_display = ('phone', 'name', 'is_admin', 'is_staff', 'is_active')
#     search_fields = ('phone', 'name')
#     list_filter = ('is_admin', 'is_staff', 'is_active')
#     ordering = ('id',)

#     fieldsets = (

#          ("Personal Info", {"fields": ("name", "phone", "email", "password")}),
#         ("Permissions", {"fields": ("is_admin", "is_staff", "is_active", "groups", "user_permissions")}),
#         ("Important Dates", {"fields": ("last_login", "created_at", "updated_at")}),
#     )
#     add_fieldsets = (
#         (
#             None,
#             {
#                 "classes": ("wide",),
#                 "fields": ("name", "phone", "email", "password1", "password2", "is_admin", "is_staff", "is_active"),
#             },
#         ),
#     )
admin.site.register(User)
# admin.site.register(User, CustomUserAdmin)