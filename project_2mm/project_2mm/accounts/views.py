from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model, authenticate, login , logout
from . import serializers
from posts import models
import uuid
import requests

User = get_user_model()

#로그인 
class Loginview(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone')
        password = request.data.get('password')
        try:
            user_info = models.UserInfo.objects.get(phone=phone)
            print(phone)
            user = authenticate(request, username=user_info.user, password=password)

            if user is not None:
                print(user)
                login(request, user)
                #토큰 생성 
                token, created = Token.objects.get_or_create(user=user)
                
                # 디버그 확인용 : 로그인 유저 
                if request.user.is_authenticated:
                    print(request.user, "님이 로그인되었습니다:", token.key)
                else:
                    print("현재 로그인되어 있지 않습니다.")

                return Response({ 'token': token.key}, status=status.HTTP_200_OK)
            else:
                return Response({'error': '로그인실패! 다시 시도'}, status=status.HTTP_401_UNAUTHORIZED)
        except models.UserInfo.DoesNotExist:
            print('뭐2')
            return Response({'error': 'userinfo가 비어있음!'}, status=status.HTTP_404_NOT_FOUND)

#로그아웃 
class LogoutView(APIView):
    def post(self, request, *args, **kwargs):
        user = request.user
        logout(request)
        #디버그 확인 :로그아웃
        if user.is_authenticated:
            print(user,"님이 로그아웃:" )
        else:
            print("현재 로그인되어 있지 않습니다.")
        return Response({'message': '로그아웃'}, status=status.HTTP_200_OK)

# #카카오 api 호출 
def get_kakao_user_info(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get('https://kapi.kakao.com/v2/user/me', headers=headers)

    print("Response status code:", response.status_code)

    if response.status_code == 200:
        user_info = response.json()
        print("User info:", user_info)
        return user_info
    else:
        print("실패실패실패!", response.content)
        return None
    
#회원가입
class SingupView(APIView):
    def post(self, request):
        serializer = serializers.UsernameSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            user = User.objects.create_user(username=username)
            user_info = models.UserInfo.objects.create(user=user)
            if user is not None :
                print("유저 생성됐다")
            if user_info is not None :
                print("유저 정보 생성됐다.")
            token, created = Token.objects.get_or_create(user=user)
            response_data = {'token': token.key, 'is_successful': True}
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            response_data = {'errors': serializer.errors, 'is_successful': False}
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, format=None):
        try:
            user_info = models.UserInfo.objects.get(user=request.user)
            print('입력받은 데이터는 ')
            print(request.data)

            serializer = serializers.UsersSerializer(user_info, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.update(user_info, serializer.validated_data)  # update 메서드 호출
                print('업데이트 됐음')
                serializer.save() 
                return Response(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except models.UserInfo.DoesNotExist:
            return Response({'detail': 'User info not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PasswordView(APIView):
    def patch(self, request):
        serializer = serializers.PasswordSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            user = request.user
            user.set_password(password)
            user.save()
            return Response({'message': '비밀번호가 업데이트되었습니다.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MypageView(APIView) :
    def get(self, request):
        user_info = models.UserInfo.objects.get(user=request.user)
        serializer = serializers.UserInfoSerializer(user_info)
        return Response(serializer.data)

    def patch(self, request, format=None):
        try:
            user_info = models.UserInfo.objects.get(user=request.user)
            serializer = serializers.UserInfoSerializer(user_info, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.update(user_info, serializer.validated_data)
                serializer.save() 
                return Response(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except models.UserInfo.DoesNotExist:
            return Response({'detail': 'User info not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GroupListCreateView(generics.CreateAPIView):
    queryset = models.Group.objects.all()
    serializer_class = serializers.GroupCreateSerializer

    def perform_create(self, serializer):
        user = self.request.user
        userinfo = user.userinfo
        
        group = serializer.save()
        group.code = uuid.uuid4()
        group.save()
        group.user.add(userinfo)
    def get(self, request):
        user = self.request.user
        groups = models.Group.get_groups_for_user(user)

        serializer = serializers.GroupDetailSerializer(groups, many=True)
        return Response(serializer.data)

class GroupDetailView(APIView):
    def get_object(self, code):
        try:
            return models.Group.objects.get(code=code)
        except models.Group.DoesNotExist:
            return None

    def get(self, request, code):
        group = self.get_object(code)
        if group is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        
        serializer = serializers.GroupSerializer(group)
        return Response(serializer.data)
    
    def patch(self, request, code, format=None):
        try:
            group = models.Group.objects.get(code=code)
            
            user_info, created = models.UserInfo.objects.get_or_create(user=request.user)
            
            # 요청한 사용자만 추가
            if not group.user.filter(user=user_info.user).exists():
                group.user.add(user_info)
            
            serializer = serializers.GroupSerializer(group, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except models.Group.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        except models.UserInfo.DoesNotExist:
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, code, format=None):
        group = self.get_object(code)
        if group is None:
            return Response({'실패': '해당 모임 없음'},status=status.HTTP_404_NOT_FOUND)
        group.delete()

        return Response({'성공': '삭제완료'}, status=status.HTTP_204_NO_CONTENT)

#유저이름 
class GetUsernameView(APIView):
    def get(self, request, *args, **kwargs):
        username = self.request.user.username
        return Response({'username': username}, status=status.HTTP_200_OK)
