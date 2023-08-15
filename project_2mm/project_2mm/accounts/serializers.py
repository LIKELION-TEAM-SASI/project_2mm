from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from posts import models

class UsernameSerializer(serializers.Serializer):
    username = serializers.CharField()
    class Meta:
        model = models.User
        fields = '__all__'
    def update(self, instance, validated_data):
        # 코드 값을 무시하고 업데이트할 필드만 validated_data에서 추출합니다.
        validated_data.pop('username', None)
        return super().update(instance, validated_data)

class UserInfoSerializer(serializers.ModelSerializer):
    username = serializers.ReadOnlyField(source='user.username')
    class Meta:
        model = models.UserInfo
        fields = ['id', 'username', 'profile']

class UsersSerializer(serializers.ModelSerializer):
    #user = serializers.ReadOnlyField(source='user.username')
    class Meta:
        model = models.UserInfo
        fields = '__all__'

    def update(self, instance, validated_data):
        # 전화번호 업데이트
        if 'phone' in validated_data:
            instance.phone = validated_data['phone']

        instance.save()
        return instance

#비밀번호 업데이트를 위해서 시리얼라이저 추가.. 
class PasswordSerializer(serializers.Serializer):
    password = serializers.CharField()

# 모임코드생성 
class GroupCreateSerializer(serializers.ModelSerializer):
    code = serializers.UUIDField(read_only=True)  # 코드 필드를 읽기 전용으로
    
    class Meta:
        model = models.Group
        fields = ['name', 'code', 'profile']  # 코드 필드도 포함

class GroupSerializer(serializers.ModelSerializer):
    user = UserInfoSerializer(many=True, source='user.all') 
    class Meta:
        model = models.Group
        fields = ['name', 'info', 'profile', 'user', 'code']

    def update(self, instance, validated_data):
        # 코드 값을 무시하고 업데이트할 필드만 validated_data에서 추출하는 메소드
        validated_data.pop('code', None)
        return super().update(instance, validated_data)

class GroupDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Group
        fields = ['name', 'info', 'profile', 'code', 'user']  # user 필드를 포함하지 않음
# class GroupDetailSerializer(serializers.ModelSerializer):
#     user = UserInfoSerializer(many=True, source='user.all')
#     class Meta:
#         model = models.Group
#         fields = '__all__'
#         read_only_fields = ['code', 'name', 'profile']