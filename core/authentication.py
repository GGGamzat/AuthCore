from rest_framework import authentication
from rest_framework import exceptions
from core.models import User


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return None

        try:
            token = auth_header.split(' ')[1]
            user = User.verify_token(token)

            if user is None:
                raise exceptions.AuthenticationFailed('Invalid token')

            return (user, token)

        except IndexError:
            raise exceptions.AuthenticationFailed('Token prefix missing')
        except Exception as e:
            raise exceptions.AuthenticationFailed(str(e))