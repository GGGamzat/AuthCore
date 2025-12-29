from django.contrib import admin
from core.models import User, Permission, Role, UserRole, Post

admin.site.register(User)
admin.site.register(Permission)
admin.site.register(Role)
admin.site.register(UserRole)
admin.site.register(Post)