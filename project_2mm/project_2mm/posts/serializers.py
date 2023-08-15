from datetime import timezone
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from accounts.serializers import UserInfoSerializer
from .models import Post, Comment, Plan,  UserInfo, Group

class PostSerializer(ModelSerializer):
    writer = UserInfoSerializer(many=True, source='user.all')
    class Meta:
        model = Post
        fields = '__all__'
    
    def get_writer(self, obj):
        return obj.writer.user.username if obj.writer else None

class AlbumSerializer(ModelSerializer):
    class Meta:
        model = Post
        fields = [ 'id', 'image','created_at' ]

class CommentSerializer(ModelSerializer):
    writer_profile = serializers.ImageField(source='writer.userinfo.profile', read_only=True)
    writer = serializers.ReadOnlyField(source='writer.username')
  
    class Meta:
        model = Comment
        fields = [ 'id','post','comment','writer','writer_profile','created_at' ]



class GroupPostSerializer(ModelSerializer):
    liked = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    writer_profile = serializers.ImageField(source='writer.userinfo.profile', read_only=True)
    writer = serializers.ReadOnlyField(source='writer.username')
    # writer = UserInfoSerializer()  # 수정된 부분
    # # Profile, name 등 원하는 정보를 필드로 추가할 수 있습니다.
    # writer_profile = serializers.CharField(source='user.all.profile')
    # writer_name = serializers.CharField(source='user.all.user.username')
    class Meta:
        model = Post
        fields = ['id', 'content', 'image', 'created_at', 'writer', 'writer_profile', 'liked']
    def get_writer(self, obj):
        return obj.writer.user.username if obj.writer else None

class GroupDetailSerializer(serializers.ModelSerializer):
    user = UserInfoSerializer(many=True, source='user.all')
    class Meta:
        model = Group
        fields = '__all__'
        read_only_fields = ['code', 'name', 'profile']

class GroupPlanSerializer(ModelSerializer) :
    class Meta :
        model = Plan
        fields = ['id', 'month', 'date', 'title', 'memo']