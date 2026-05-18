from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model  = User
        fields = ['email', 'name', 'password', 'role']

    def create(self, validated_data):
        user = User(
            email = validated_data['email'],
            name  = validated_data.get('name', ''),
            role  = validated_data.get('role', 'user'),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email    = serializers.EmailField()
    password = serializers.CharField()