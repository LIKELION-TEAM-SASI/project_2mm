from django.urls import path
from . import views

urlpatterns = [


   
    # 앨범
    path('group/<uuid:group_code>/album/', views.AlbumViewSet.as_view(), name='album-list'), 
    path('group/<uuid:group_code>/album/<int:post_id>/', views.AlbumDetailViewSet.as_view(), name='album-detail'),
    path('group/<uuid:group_code>/album/<int:post_id>/download/', views.AlbumDownloadView.as_view({'get': 'download'}), name='album-download'),

    # 모임별 게시글
    path('group/<uuid:group_code>/posts/', views.GroupPostView.as_view(), name='post_list'),
    path('group/<uuid:code>/posts/<int:post_id>/', views.GroupPostDetailView.as_view(), name='post_detail'),

    #게시글별 댓글 
    path('group/<uuid:group_code>/posts/<int:post_id>/comments/', views.CommentView.as_view(), name='comment-list'),
    path('group/<uuid:group_code>/posts/<int:post_id>/comments/<int:comment_id>/', views.CommentView.as_view(), name='comment-detail'),
   
    # 모임별 일정 
    path('group/<uuid:group_code>/plans/', views.GroupPlanView.as_view(), name='plan_list'),
    path('group/<uuid:group_code>/plans/<int:plan_id>/', views.GroupPlanDetailView.as_view(), name='group-plan-detail')

    
]
