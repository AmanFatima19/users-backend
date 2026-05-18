from django.urls import path
from . import views

app_name = "users"

urlpatterns = [
    # Public routes — no token required
    path('signup/',        views.signup_view,       name='signup'),
    path('login/',         views.login_view,         name='login'),
    path('logout/',        views.logout_view,        name='logout'),
    path('token/refresh/', views.refresh_token_view, name='token-refresh'),

    # Protected routes — cookie required
    path('profile/', views.profile_view,       name='profile'),
    path('update/',  views.update_profile_view, name='update'),
    path('delete/',  views.delete_account_view, name='delete'),

    # Admin only routes
    path('all-users/',            views.all_users_view,    name='all-users'),
    path('admin-only/',           views.admin_only_view,   name='admin-only'),
    path('update/<int:user_id>/', views.update_user_by_id, name='update-by-id'),
    path('delete/<int:user_id>/', views.delete_user_by_id, name='delete-by-id'),
]