from django.conf import settings


SESSION_HEADER_NAME = 'HTTP_X_SESSION_ID'


class SessionMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from .helpers.session import Context as SessionContext
        from uuid import UUID

        session = SessionContext(request)
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None) or request.META.get(SESSION_HEADER_NAME, None)
        session_uuid = None

        if session_key:
            try:
                session_uuid = UUID(session_key)
            except:
                pass

        if session_uuid:
            session.load(session_uuid)
        else:
            session.init()

        response = self.get_response(request)
        session.save()
        session_key = str(session.uuid)
        response[SESSION_HEADER_NAME] = session_key
        response.set_cookie(
            settings.SESSION_COOKIE_NAME,
            value=session_key,
            max_age=settings.SESSION_COOKIE_AGE,
            expires=None,
            path=settings.SESSION_COOKIE_PATH,
            domain=settings.SESSION_COOKIE_DOMAIN,
            secure=settings.SESSION_COOKIE_SECURE,
            httponly=settings.SESSION_COOKIE_HTTPONLY)

        return response

"""
class AuthenticationMiddleware(object):
    def __init__(self, get_response):
        from .models import TokenCredentialDirectory
        from re import compile

        self.get_response = get_response

        token_directories = []

        for token_credential_directory in TokenCredentialDirectory.objects.all().prefetch_related('options', 'provided_evidences'):
            pattern = token_credential_directory.get('HTTP_AUTHORIZATION_HEADER_VALUE_PATTERN', None)

            if pattern:
                token_directories.append((
                    compile(pattern),
                    token_credential_directory,
                    list(token_credential_directory.provided_evidences.all())))

        self.token_directories = token_directories

    def __call__(self, request):
        from .models import _tznow
        from .models import TokenCredential

        authorization = request.META.get('HTTP_AUTHORIZATION', None)

        if authorization:
            now = _tznow()

            for token_directory in self.token_directories:
                match = token_directory[0].match(authorization)

                if match:
                    token_value = match.group('value')

                    try:
                        token_credential = TokenCredential.objects.get(
                            directory=token_directory[1],
                            public_value=token_value,
                            valid_from__lte=now,
                            valid_till__gte=now)

                        principal = token_credential.principal
                        principal._load_authentication_context(token_directory[2])
                        request.user = principal
                        request.principal = principal
                        break
                    except TokenCredential.DoesNotExist:
                        pass

        response = self.get_response(request)

        return response
"""
