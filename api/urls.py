from django.urls import path
from .views import (
    register_view, 
    note_list_create_view, 
    note_detail_view,
    logout_view, 
    admin_login_view, 
    admin_toggle_user_status_view,
    profile_view,
    refresh_token_view,
    get_all_users,
    CustomTokenObtainPairView,
    CustomTokenRefreshView
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('register/', register_view),
    # path('login/', TokenObtainPairView.as_view()),
    # path('token/refresh/', TokenRefreshView.as_view()),
    path('login/', CustomTokenObtainPairView.as_view()),
    # path('token/refresh/', CustomTokenRefreshView.as_view()),
    path('token/refresh/',refresh_token_view),
    path('logout/', logout_view),
    path('notes/', note_list_create_view),
    path('notes/<int:pk>/', note_detail_view),
    path('admin/login/', admin_login_view),
    path('admin/toggle-user/<int:pk>/', admin_toggle_user_status_view),
    path('profile/', profile_view, name='user-profile'),
    path('admin/users/',get_all_users)
]
