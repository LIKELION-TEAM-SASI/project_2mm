from django.urls import path, include
from . import views

urlpatterns = [
    #로그인 
    path('api/login/', views.Loginview.as_view(), name='phone_login_view'),
    path('api/logout/', views.LogoutView.as_view(), name='phone_logout_view'),

    #소셜로그인 
    path('authaccounts/', include('allauth.urls')),
    # path('authaccounts/kakao/login/callback/', views.handle_kakao_callback, name='kakao_callback'),

    # path('accounts/kakao/login/', views.kakao_login, name='kakao_login'),
    # path('accounts/kakao/callback/', views.kakao_callback, name='kakao_callback'),
    # path('accounts/kakao/login/finish/', views.KakaoLogin.as_view(), name='kakao_login_todjango'),

    #회원가입 
    path('signup/', views.SingupView.as_view(), name='signup'),
    path('update-password/', views.PasswordView.as_view(), name='update-password'),

    # 모임
    path('group/', views.GroupListCreateView.as_view(), name='group-list-create'),
    path('group/<uuid:code>/', views.GroupDetailView.as_view(http_method_names=['get', 'patch', 'delete']), name='group-detail'),

    #유저이름 
    path('get-username/', views.GetUsernameView.as_view(), name='get-username'),
    # 마이페이지 
    path('mypage/', views.MypageView.as_view(), name='mypage'),
]