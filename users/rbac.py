from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.role.name == 'Admin'

class IsModerator(BasePermission):
    def has_permission(self, request, view):
        return request.user.role.name == 'Moderator'

class IsUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.role.name == 'User'
