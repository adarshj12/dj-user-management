from rest_framework import serializers
from .models import Note, CustomUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken,RefreshToken
import logging

logger = logging.getLogger(__name__)

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        # fields = ['username', 'password', 'profileImage']  
        fields = [
            'id',
            'username',
            'password',
            'profileImage',
            'is_active',
            'date_joined',
        ]

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = '__all__'
        read_only_fields = ['user']


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def post(self, request, *args, **kwargs):
        # Call the parent class's post method to handle the refresh logic
        response = super().post(request, *args, **kwargs)
        print('hiooyoyuoy',response)
        # Extract the refresh token from the request data
        refresh_token = request.data.get('refresh')
        print('hyyhyhrh',refresh_token)
        if not refresh_token:
            logger.error("No refresh token provided")
            return {"message":"No Token Provided"}

        try:
            # Create a RefreshToken object to generate a new access token
            refresh = RefreshToken(refresh_token)
            access = refresh.access_token

            print('sfsgsg',refresh,access)
            # Get the user from the request or token
            user = request.user if hasattr(request, 'user') else refresh.get('user_id')

            print('gjgjgry',user)
            # Add custom key (e.g., admin: true) if the user is a superuser
            if user and user.is_superuser:
                access['admin'] = True
                logger.debug(f"Added admin claim for user {user.username}")
            
            print('gjgjgry',access)
            # Update the response with the modified access token
            response.data['access'] = str(access)
            return response
        except Exception as e:
            logger.error(f"Error processing refresh token: {str(e)}")
            return e

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["username"] = user.username
        token["profileImage"] = user.profileImage

        return token          
