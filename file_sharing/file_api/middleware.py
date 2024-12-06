from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.exceptions import AuthenticationFailed
from .models import BlacklistedToken

class BlacklistAccessTokenMiddleware(MiddlewareMixin):
    def process_request(self, request):

        access_token = request.headers.get('Authorization')

        if access_token and access_token.startswith('Bearer '):
            access_token = access_token[7:]


            try:
                AccessToken(access_token)  # Decode the access token to check if it's valid
                if BlacklistedToken.objects.filter(token=access_token).exists():
                    raise AuthenticationFailed('Token is blacklisted.')
            except Exception:
                raise AuthenticationFailed('Invalid token.')
