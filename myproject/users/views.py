from __future__ import annotations

from django.contrib.auth import authenticate, get_user_model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from .serializers import SignupSerializer, LoginSerializer

User = get_user_model()


# ───────────────────────────────
# SIGNUP
# ───────────────────────────────
@api_view(['POST'])
@permission_classes([AllowAny])
def signup_view(request):
    serializer = SignupSerializer(data=request.data)

    if serializer.is_valid():
        user    = serializer.save()
        refresh = RefreshToken.for_user(user)
        access  = str(refresh.access_token)
        refresh = str(refresh)

        # Build response
        response = Response({
            'message': 'Account created successfully!',
            'role'   : user.role,
        }, status=status.HTTP_201_CREATED)

        # Set access token in cookie
        response.set_cookie(
            key      = 'access_token',  # cookie name
            value    = access,           # token value
            httponly = True,             # JS cannot access this cookie
            secure   = False,            # set True in production (HTTPS)
            samesite = 'Lax',            # protection against CSRF
            max_age  = 60 * 60,          # 1 hour in seconds
        )

        # Set refresh token in cookie
        response.set_cookie(
            key      = 'refresh_token',
            value    = refresh,
            httponly = True,
            secure   = False,
            samesite = 'Lax',
            max_age  = 60 * 60 * 24 * 7,  # 7 days
        )

        return response

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ───────────────────────────────
# LOGIN
# ───────────────────────────────
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)

    if serializer.is_valid():
        email    = serializer.validated_data['email']
        password = serializer.validated_data['password']

        # Check email and password against database
        user = authenticate(request, email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access  = str(refresh.access_token)
            refresh = str(refresh)

            response = Response({
                'message': 'Logged in successfully!',
                'role'   : user.role,
            })

            # Set access token in cookie
            response.set_cookie(
                key      = 'access_token',
                value    = access,
                httponly = True,
                secure   = False,
                samesite = 'Lax',
                max_age  = 60 * 60,          # 1 hour
            )

            # Set refresh token in cookie
            response.set_cookie(
                key      = 'refresh_token',
                value    = refresh,
                httponly = True,
                secure   = False,
                samesite = 'Lax',
                max_age  = 60 * 60 * 24 * 7,  # 7 days
            )

            return response

        return Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ───────────────────────────────
# LOGOUT
# ───────────────────────────────
@api_view(['POST'])
@permission_classes([AllowAny])
def logout_view(request):
    response = Response({'message': 'Logged out successfully!'})

    # Delete both cookies
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')

    return response


# ───────────────────────────────
# TOKEN REFRESH
# ───────────────────────────────
@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_view(request):
    # Get refresh token from cookie
    refresh_token = request.COOKIES.get('refresh_token')

    if not refresh_token:
        return Response(
            {'error': 'Refresh token not found'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    try:
        refresh    = RefreshToken(refresh_token)
        new_access = str(refresh.access_token)

        response = Response({'message': 'Token refreshed successfully!'})

        # Set new access token in cookie
        response.set_cookie(
            key      = 'access_token',
            value    = new_access,
            httponly = True,
            secure   = False,
            samesite = 'Lax',
            max_age  = 60 * 60,  # 1 hour
        )

        return response

    except Exception:
        return Response(
            {'error': 'Refresh token is invalid or expired'},
            status=status.HTTP_401_UNAUTHORIZED
        )


# ───────────────────────────────
# HELPER FUNCTION
# Get user from cookie token
# ───────────────────────────────
def get_user_from_cookie(request):
    # Get access token from cookie
    token = request.COOKIES.get('access_token')

    if not token:
        return None

    try:
        access_token = AccessToken(token)            # verify token
        user_id      = access_token['user_id']       # extract user id
        user         = User.objects.get(id=user_id)  # get user from db
        return user
    except Exception:
        return None


# ───────────────────────────────
# PROFILE
# ───────────────────────────────
@api_view(['GET'])
@permission_classes([AllowAny])
def profile_view(request):
    # Get user from cookie
    user = get_user_from_cookie(request)

    if not user:
        return Response(
            {'error': 'Please login first'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    return Response({
        'email': user.email,
        'name' : user.name,
        'role' : user.role,
    })


# ───────────────────────────────
# UPDATE OWN PROFILE
# ───────────────────────────────
@api_view(['PUT'])
@permission_classes([AllowAny])
def update_profile_view(request):
    # Get user from cookie
    user = get_user_from_cookie(request)

    if not user:
        return Response(
            {'error': 'Please login first'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Update only provided fields, keep old values if not provided
    user.name  = request.data.get('name',  user.name)
    user.email = request.data.get('email', user.email)

    # Update password if provided
    new_password = request.data.get('password')
    if new_password:
        user.set_password(new_password)

    user.save()
    return Response({
        'message': 'Profile updated successfully!',
        'email'  : user.email,
        'name'   : user.name,
        'role'   : user.role,
    })


# ───────────────────────────────
# DELETE OWN ACCOUNT
# ───────────────────────────────
@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_account_view(request):
    # Get user from cookie
    user = get_user_from_cookie(request)

    if not user:
        return Response(
            {'error': 'Please login first'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    user.delete()

    # Clear cookies after account deletion
    response = Response({'message': 'Account deleted successfully!'})
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response


# ───────────────────────────────
# ALL USERS — Admin only
# ───────────────────────────────
@api_view(['GET'])
@permission_classes([AllowAny])
def all_users_view(request):
    # Get user from cookie
    user = get_user_from_cookie(request)

    if not user:
        return Response(
            {'error': 'Please login first'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Check admin role
    if user.role != 'admin':
        return Response(
            {'error': 'Only admin can access this'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Get all users from database
    users = User.objects.all()
    data  = []
    for u in users:
        data.append({
            'id'   : u.id,
            'email': u.email,
            'name' : u.name,
            'role' : u.role,
        })

    return Response(data)


# ───────────────────────────────
# UPDATE USER BY ID — Admin only
# ───────────────────────────────
@api_view(['PUT'])
@permission_classes([AllowAny])
def update_user_by_id(request, user_id):
    # Get user from cookie
    user = get_user_from_cookie(request)

    if not user:
        return Response(
            {'error': 'Please login first'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Check admin role
    if user.role != 'admin':
        return Response(
            {'error': 'Only admin can update users'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Find target user by ID
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Update fields
    target_user.name  = request.data.get('name',  target_user.name)
    target_user.email = request.data.get('email', target_user.email)

    new_password = request.data.get('password')
    if new_password:
        target_user.set_password(new_password)

    target_user.save()
    return Response({
        'message': 'User updated successfully!',
        'id'     : target_user.id,
        'email'  : target_user.email,
        'name'   : target_user.name,
        'role'   : target_user.role,
    })


# ───────────────────────────────
# DELETE USER BY ID — Admin only
# ───────────────────────────────
@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_user_by_id(request, user_id):
    # Get user from cookie
    user = get_user_from_cookie(request)

    if not user:
        return Response(
            {'error': 'Please login first'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Check admin role
    if user.role != 'admin':
        return Response(
            {'error': 'Only admin can delete users'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Find target user by ID
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    target_user.delete()
    return Response(
        {'message': f'User {user_id} deleted successfully!'},
        status=status.HTTP_200_OK
    )


# ───────────────────────────────
# ADMIN ONLY VIEW
# ───────────────────────────────
@api_view(['GET'])
@permission_classes([AllowAny])
def admin_only_view(request):
    # Get user from cookie
    user = get_user_from_cookie(request)

    if not user:
        return Response(
            {'error': 'Please login first'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Check admin role
    if user.role != 'admin':
        return Response(
            {'error': 'Only admin can access this'},
            status=status.HTTP_403_FORBIDDEN,
        )

    return Response({'message': 'Welcome Admin!'})