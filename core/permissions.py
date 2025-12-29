from rest_framework import permissions
from core.models import Permission, UserRole


class HasPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        if not request.user or not request.user.is_active:
            return False

        if request.user.is_admin:
            return True

        if hasattr(view, 'get_required_permission'):
            required_permission = view.get_required_permission()
        else:
            required_permission = getattr(view, 'required_permission', None)

        if not required_permission:
            return True

        user_roles = UserRole.objects.filter(user=request.user).select_related('role')

        for user_role in user_roles:
            role_permissions = user_role.role.permissions.filter(codename=required_permission)
            if role_permissions.exists():
                return True

        return False


class IsAdminUser(permissions.BasePermission):

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_active and request.user.is_admin)


class IsOwnerOrHasPermission(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'created_by') and obj.created_by == request.user:
            return True

        permission_checker = HasPermission()
        return permission_checker.has_permission(request, view)