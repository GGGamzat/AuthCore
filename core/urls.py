from django.urls import path, include
from rest_framework.routers import DefaultRouter
from core import views

router = DefaultRouter()
router.register(r'admin/permissions', views.PermissionViewSet, basename='permission')
router.register(r'admin/roles', views.RoleViewSet, basename='role')
router.register(r'admin/user-roles', views.UserRoleViewSet, basename='userrole')

urlpatterns = [
    # Аутентификация
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('delete-account/', views.UserDeleteView.as_view(), name='delete-account'),

    # Работа с постами (минимальный бизнес-объект)
    path('posts/', views.PostListView.as_view(), name='post-list'),
    path('posts/my/', views.MyPostsView.as_view(), name='my-posts'),
    path('posts/<int:pk>/', views.PostDetailView.as_view(), name='post-detail'),

    # Админ-панель
    path('', include(router.urls)),
]