from django.conf import settings


class SessionMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from .helpers.session import Context as SessionContext
        from uuid import UUID

        session = SessionContext(request)
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None) or request.META.get('HTTP_X_SESSION_ID', None)
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
        response['X-Session-ID'] = session_key
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
