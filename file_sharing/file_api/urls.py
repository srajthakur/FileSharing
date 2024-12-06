from django.urls import path
from .views import SignUpView, LoginView, FileUploadView, FileDownloadView, FileListView, FileAccessView, \
    VerifyEmailView, LogoutView

urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='login'),
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('download-file/<int:file_id>/', FileDownloadView.as_view(), name='file-download'),
    path('file-access/<str:encrypted_link>/', FileAccessView.as_view(), name='file-access'),
    path('list-files/', FileListView.as_view(), name='file-list'),
    path('verify-email/<str:uidb64>/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
]
