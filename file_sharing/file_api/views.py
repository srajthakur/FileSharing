from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, TokenError
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from cryptography.fernet import Fernet, InvalidToken
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from .models import File
from .serializers import FileSerializer, LoginSerializer
from .permission import IsOpsUser, IsClientUser
KEY = Fernet.generate_key()
cipher_suite = Fernet(KEY)
from .models import BlacklistedToken

class SignUpView(APIView):
    def post(self, request):
        try:
            User = get_user_model()
            username = request.data.get('username')
            email = request.data.get('email')
            password = request.data.get('password')
            first_name= request.data.get("first_name")
            last_name= request.data.get("last_name")
            user_type= request.data.get("user_type")
            if User.objects.filter(email=email).exists():
                return Response({'message': 'Email already registered.'}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects.filter(username=username).exists():
                return Response({'message': 'username already registered.'}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.create_user(username=username,
                                            email=email,
                                            password=password,
                                            first_name=first_name,
                                            last_name=last_name,
                                            user_type=user_type,
                                            )
            token = AccessToken.for_user(user)
            token['email_verification'] = True
            token.set_exp(lifetime=timedelta(minutes=10))


            uid = urlsafe_base64_encode(str(user.pk).encode())
            verification_url = f"{get_current_site(request).domain}/api/verify-email/{uid}/{token}/"


            try:
                send_mail(
                    'Verify Your Email',
                    f'Click here to verify your email: {verification_url}',
                    'sender_email',
                    [email],
                )

                return Response({'message': 'Account created. Please check your email for verification.'},
                                status=status.HTTP_201_CREATED)
            except:
                return Response({'message': 'Account created.',
                                 'email_verification_url':verification_url
                                 },
                                status=status.HTTP_201_CREATED)
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyEmailView(APIView):
    def get(self, request, uidb64, token):
        try:

            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_user_model().objects.get(pk=uid)


            access_token = AccessToken(token)
            if access_token['email_verification'] and access_token['user_id'] == user.id:
                user.is_verified = True
                user.save()
                return HttpResponse("Your email has been verified successfully!")
            else:
                return HttpResponse("Invalid verification token.", status=400)

        except (TokenError, KeyError):
            return HttpResponse("Invalid or expired token.", status=400)
        except get_user_model().DoesNotExist:
            return HttpResponse("Invalid user ID.", status=400)



class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LogoutView(APIView):
    def post(self, request):
        try:

            refresh_token = request.data.get('refresh')
            access_token = request.headers.get('Authorization')
            if not refresh_token:
                return Response({'message': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)


            token = RefreshToken(refresh_token)

            token.blacklist()
            access_token_obj = AccessToken(access_token)
            BlacklistedToken.objects.create(token=str(access_token_obj))

            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'message': f'Error: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
class FileUploadView(APIView):
    permission_classes = [IsAuthenticated, IsOpsUser]

    def post(self, request):
        try:
            file = request.FILES.get('file')

            if file.content_type not in File.allowed_types:
                return Response({'message': 'Invalid file type. Only pptx, docx, and xlsx are allowed.'}, status=status.HTTP_400_BAD_REQUEST)

            file_obj = File.objects.create(file=file, uploaded_by=request.user)
            serializer = FileSerializer(file_obj)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:

            return Response({'message': 'An error occurred while uploading the file.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileListView(APIView):
    permission_classes = [IsAuthenticated, IsClientUser]

    def get(self, request):
        try:
            files = File.objects.all()
            serializer = FileSerializer(files, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:

            return Response({'message': 'An error occurred while retrieving files.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileDownloadView(APIView):
    permission_classes = [IsAuthenticated, IsClientUser]

    def get(self, request, file_id):
        try:
            file = get_object_or_404(File, id=file_id)

            if request.user.user_type != 'CLIENT':
                return Response({'message': 'Only Client Users can download files.'}, status=status.HTTP_403_FORBIDDEN)

            download_link = cipher_suite.encrypt(file.file.name.encode()).decode()
            return Response({'download-link': download_link, 'message': 'success'}, status=status.HTTP_200_OK)
        except Exception as e:

            return Response({'message': 'An error occurred while generating the download link.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileAccessView(APIView):
    permission_classes = [IsAuthenticated, IsClientUser]

    def get(self, request, encrypted_link):
        try:
            decrypted_link = cipher_suite.decrypt(encrypted_link.encode()).decode()
            file = get_object_or_404(File, file=decrypted_link)

            if request.user.user_type != 'CLIENT':
                return Response({'message': 'Only Client Users can access files.'}, status=status.HTTP_403_FORBIDDEN)

            with open(file.file.path, 'rb') as f:
                response = HttpResponse(f.read(), content_type="application/octet-stream")
                response['Content-Disposition'] = f'attachment; filename="{file.file.name}"'
                return response
        except InvalidToken:

            return Response({'message': 'Invalid download link.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:

            return Response({'message': 'An error occurred while accessing the file.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)