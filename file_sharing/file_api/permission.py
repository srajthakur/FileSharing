from rest_framework.permissions import BasePermission

class IsOpsUser(BasePermission):

    def has_permission(self, request, view):
        return  request.user.user_type == 'OPS'

class IsClientUser(BasePermission):

    def has_permission(self, request, view):
        return  request.user.user_type == 'CLIENT'
