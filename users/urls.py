from django.urls import path
from .views import RegisterView, LoginView, LogoutView, AdminView, ModeratorView, UserView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Role-based access endpoints
    path('admin-view/', AdminView.as_view(), name='admin-view'),
    path('moderator-view/', ModeratorView.as_view(), name='moderator-view'),
    path('user-view/', UserView.as_view(), name='user-view'),
]
