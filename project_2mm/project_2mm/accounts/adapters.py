
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from posts.models import UserInfo 
from accounts.views import get_kakao_user_info  

from django.contrib.auth.models import User

class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form=form)
        
        if sociallogin.account.provider == 'kakao':
            access_token = sociallogin.token.token
            user_info = get_kakao_user_info(access_token)
            if user_info:
                nickname = user_info.get('kakao_account', {}).get('profile', {}).get('nickname')
                if nickname:
                    try:
                        existing_user = User.objects.get(username=nickname)
                        UserInfo.objects.get_or_create(user=existing_user)
                    except User.DoesNotExist:
                        pass
        
        return user
