
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta

# Role model to define different roles like Admin, User, Moderator
from django.db import models

class Role(models.Model):
    ADMIN = 'Admin'
    USER = 'User'
    MODERATOR = 'Moderator'

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (USER, 'User'),
        (MODERATOR, 'Moderator'),
    ]
    
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)

    def __str__(self):
        return self.name


# Extending the built-in User model to include a role and failed login attempts

class CustomUser(AbstractUser):
    # Adding related_name to avoid conflicts
    role = models.ForeignKey('Role', on_delete=models.SET_NULL, null=True, blank=True)
    failed_attempts = models.IntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)

    # Custom reverse accessors for groups and user_permissions
    groups = models.ManyToManyField(
        'auth.Group', 
        related_name='customuser_set',  # Custom related_name to prevent conflict
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission', 
        related_name='customuser_set',  # Custom related_name to prevent conflict
        blank=True
    )

    def __str__(self):
        return self.username

    def is_account_locked(self):
        if self.lockout_until and timezone.now() < self.lockout_until:
            return True
        return False

    def unlock_account(self):
        if self.lockout_until and timezone.now() >= self.lockout_until:
            self.failed_attempts = 0
            self.lockout_until = None
            self.save()