from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions, status
from rest_framework.response import Response
from .models import CustomUser,Note
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .serializers import UserSerializer, NoteSerializer, CustomTokenObtainPairSerializer, CustomTokenRefreshSerializer
from .permissions import IsOwnerOrAdmin
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework.permissions import AllowAny
from django.shortcuts import get_object_or_404
from cloudinary.uploader import upload,destroy
from urllib.parse import urlparse
from django.contrib.auth import get_user_model
import jwt
import os

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_view(request):
    User = get_user_model()
    refresh_token_str = request.data.get('refresh')

    if not refresh_token_str:
        return Response(
            {"error": "Refresh token is required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        old_token = RefreshToken(refresh_token_str)

        # Get user from token claims
        user_id = old_token["user_id"]
        user = User.objects.get(id=user_id)
    
        decoded = jwt.decode(refresh_token_str, options={"verify_signature": False})

        old_token.blacklist()

        new_token = RefreshToken.for_user(user)
        new_access_token = new_token.access_token
        if decoded.get("admin"):
            new_access_token["admin"] = True
            new_token["admin"] = True
        else :
            new_access_token["username"] = user.username    

        return Response({
            "access": str(new_access_token),
            "refresh": str(new_token)
        }, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response(
            {"error": "User not found for token"},
            status=status.HTTP_401_UNAUTHORIZED
        )
    except (TokenError, InvalidToken) as e:
        print(f"Token error: {str(e)}") 
        return Response(
            {"error": str(e)},
            status=status.HTTP_401_UNAUTHORIZED
        )
    except Exception as e:
        return Response(
            {"error": f"An error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
def register_view(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
@permission_classes([permissions.IsAuthenticated])
def note_list_create_view(request):
    if request.method == 'GET':
        notes = Note.objects.filter(user=request.user)
        serializer = NoteSerializer(notes, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = NoteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'PATCH','DELETE'])
@permission_classes([permissions.IsAuthenticated, IsOwnerOrAdmin])
def note_detail_view(request, pk):
    note = get_object_or_404(Note, pk=pk)

    if request.method == 'GET':
        serializer = NoteSerializer(note)
        return Response(serializer.data)

    elif request.method in ['PUT', 'PATCH']:
        serializer = NoteSerializer(note, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        note.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
def logout_view(request):
    try:
        refresh = RefreshToken(request.data['refresh'])
        refresh.blacklist()
        return Response(status=status.HTTP_205_RESET_CONTENT)
    except Exception:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def admin_login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if username == os.getenv("ADMIN_USERNAME") and password == os.getenv("ADMIN_PASSWORD"):
        user, created = CustomUser.objects.get_or_create(username=username, is_staff=True, is_superuser=True)
        if created:
            user.set_password(password)
            user.save()
        # token = RefreshToken.for_user(user)
        # return Response({
        #     'access': str(token.access_token),
        #     'refresh': str(token)
        # })
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token['admin'] = True
        refresh['admin'] = True    

        return Response({
            'access': str(access_token),
            'refresh': str(refresh)
        })
    return Response({'error': 'Invalid admin credentials'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['PATCH'])
@permission_classes([permissions.IsAdminUser])
def admin_toggle_user_status_view(request, pk):
    user = get_object_or_404(CustomUser, pk=pk)
    user.is_active = not user.is_active
    user.save()
    return Response({'is_active': user.is_active})

@api_view(['GET', 'PATCH'])
def profile_view(request):
    user = request.user

    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response(serializer.data)

    elif request.method == 'PATCH':
        print(request.data)
        print(request.FILES)

        if request.FILES.get('image'):
            current_serializer = UserSerializer(user)
            current_image_url = current_serializer.data.get("profileImage")

            if current_image_url:
                print(current_image_url, 'tester')
                path = urlparse(current_image_url).path
                filename = os.path.basename(path)
                cloudinary_id = os.path.splitext(filename)[0]
                print(cloudinary_id)
                destroy(cloudinary_id)  

            image = request.FILES['image']
            result = upload(image)
            image_url = result.get('secure_url')
            request.data._mutable = True  # if request.data is QueryDict
            request.data['profileImage'] = image_url


        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=400)
    
@api_view(['GET'])
@permission_classes([permissions.IsAdminUser])
def get_all_users(request):
    users = CustomUser.objects.filter(is_staff=False, is_superuser=False)
    serializer = UserSerializer(users,many=True)
    return Response(serializer.data)   
