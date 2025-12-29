from rest_framework import generics, viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from core.models import User, Permission, Role, UserRole, Post
from core.serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,
    PermissionSerializer, RoleSerializer, UserRoleAssignmentSerializer,
    PostSerializer
)
from core.permissions import HasPermission, IsAdminUser, IsOwnerOrHasPermission


class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegistrationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        token = user.generate_token()

        return Response({
            'user': UserProfileSerializer(user).data,
            'token': token
        }, status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        token = user.generate_token()

        return Response({
            'user': UserProfileSerializer(user).data,
            'token': token
        })


class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        return Response({"message": "Successfully logged out"})


class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class UserDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.soft_delete()
        return Response({"message": "Account deleted successfully"},
                        status=status.HTTP_204_NO_CONTENT)


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    required_permission = 'manage_permissions'


class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    required_permission = 'manage_roles'


class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleAssignmentSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    required_permission = 'assign_roles'


class PostListView(generics.ListCreateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated, HasPermission]
    # required_permission = 'view_posts'

    def get_required_permission(self):
        if self.request.method == 'GET':
            return 'view_posts'
        elif self.request.method == 'POST':
            return 'create_posts'
        return None

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class PostDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrHasPermission]

    def get_required_permission(self):
        if self.request.method == 'GET':
            return 'view_posts'
        elif self.request.method in ['PUT', 'PATCH']:
            return 'edit_posts'
        elif self.request.method == 'DELETE':
            return 'delete_posts'
        return None


class MyPostsView(generics.ListAPIView):
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Post.objects.filter(created_by=self.request.user).order_by('-created_at')