from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import status
from rest_framework.authtoken.models import Token

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login , logout
from posts.models import UserInfo
from django.contrib.auth.decorators import login_required
from allauth.socialaccount.models import SocialApp, SocialToken
from oauthlib.oauth2 import OAuth2Error

from .serializers import UserInfoSerializer, UsernameSerializer

from django.shortcuts import redirect
from . import serializers
from posts import models
#from phonenumber_field.modelfields import PhoneNumber
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

# class KakaoSignInView(APIView) :
#     def get(self, request) :
#         app_key = '2103c1e9e9ec3c9736da56b28c6bbe14'
#         redirect_uri = 'http://127.0.0.1:8000/authaccounts/kakao/login/callback/'
#         kakao_auth_api = 'https://kauth.kakao.com/oauth/authorize?response_type=code'
#         return redirect(
#             f'{kakao_auth_api}&client_id={app_key}&redirect_uri={redirect_uri}'
#         )
# #https://accounts.kakao.com/login/
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
    
# #카카오 토큰 값 부여 
# def handle_kakao_callback(request):
#     access_token = request.GET.get('access_token')
#     try:
#         kakao_app = SocialApp.objects.get(provider='kakao')

#         user_info = get_kakao_user_info(access_token)  

#         fetched_name = user_info.get('properties', {}).get('nickname')
#         user = request.user

#         if user.is_authenticated:
        
#             userinfo, created = UserInfo.objects.get_or_create(user=user)
#             userinfo.user = fetched_name
#             userinfo.save()

#             return HttpResponse("UserInfo 업데이트 .")
#         else:
#             return HttpResponse("UserInfo 업데이트 실패")
#     except OAuth2Error:
#         return HttpResponse("에러")

# class KakaoLoginView(APIView):
#     def post(self, request, *args, **kwargs):
#         kakao_token = request.data.get('kakaoToken')
#         if kakao_token:
#             # 카카오톡 토큰 검증
#             response = requests.get(f'https://kapi.kakao.com/v2/user/me', headers={
#             'Authorization': f'Bearer {kakao_token}'
#             })

#             if response.status_code == 200:
#                 user_info = response.json()
#                 kakao_id = user_info['id']

#                 # SocialAccount를 통해 User 객체 가져오기
#                 try:
#                     social_account = SocialAccount.objects.get(provider='kakao', uid=kakao_id)
#                     user = social_account.user
#                 except SocialAccount.DoesNotExist:
#                     return Response({'message': '소셜 계정 연결 실패'}, status=status.HTTP_400_BAD_REQUEST)

#                 # UserInfo 모델에 추가 정보 저장 또는 업데이트
#                 # nickname = user_info.get('kakao_account', {}).get('profile', {}).get('nickname')
            
#                 # userinfo, _ = UserInfo.objects.get_or_create(user=user)
#                 # userinfo.nickname = nickname
#                 # userinfo.save()
#                 # return Response({'message': '로그인 성공'}, status=status.HTTP_200_OK)
            
#         return Response({'message': '로그인 실패'}, status=status.HTTP_400_BAD_REQUEST)
#회원가입
class SingupView(APIView):
    # def get(self, request):
    #     queryset = models.User.objects.all()
    #     serializer = serializers.UsersSerializer(queryset, many=True)  # queryset은 여러 개의 유저를 포함할 수 있으므로 many=True 옵션 사용
    #     return Response(serializer.data)    

    def post(self, request):
        # 여기서 받은 사용자 이름으로 일단 create user 하고 나머지 정보는 patch로 수정하는 식으로 
        serializer = serializers.UsernameSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            #self.request.session['username'] = username
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
                #print(serializer.error)
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
                group.user.add(user_info)  # Add the user to the group
            
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

        # try:
        #     group = models.Group.objects.get(code=code)
    
        #     # Check if the user is not in the group
        #     user_info, created = models.UserInfo.objects.get_or_create(user=request.user)
        #     if not group.user.filter(user=user_info.user).exists():
        #         group.user.add(user_info)  # Add the user to the group
    
        #     serializer = serializers.GroupDetailSerializer(group, data=request.data, partial=True)
        #     if serializer.is_valid():
        #         serializer.save()
        #         return Response(serializer.data)
        #     else:
        #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # except models.Group.DoesNotExist:
        #     return Response(status=status.HTTP_404_NOT_FOUND)
        # except models.UserInfo.DoesNotExist:
        #     return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        # except Exception as e:
        #     return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # try:
        #     queryset = models.Group.objects.get(code=code)
        #     serializer = serializers.GroupDetailSerializer(queryset, data=request.data, partial=True)
        #     if serializer.is_valid():
        #         serializer.save()
        #         return Response(serializer.data)
        #     else:
        #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # except models.Group.DoesNotExist:
        #     return Response(status=status.HTTP_404_NOT_FOUND)
        # except Exception as e:
        #     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, code, format=None):
        group = self.get_object(code)
        if group is None:
            return Response({'실패': '해당 모임 없음'},status=status.HTTP_404_NOT_FOUND)
        group.delete()

        return Response({'성공': '삭제완료'}, status=status.HTTP_204_NO_CONTENT)

# 화상 공유시 url 발급 
class CurrentPageURL(APIView):
    def get(self, request):
        current_url = request.build_absolute_uri()
        return Response({'current_url': current_url})
    

#유저이름 
class GetUsernameView(APIView):
    def get(self, request, *args, **kwargs):
        username = self.request.user.username
        return Response({'username': username}, status=status.HTTP_200_OK)

     