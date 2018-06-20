from re import sub
from rest_framework.authtoken.models import Token
from talos import middleware
from talos.models import Principal
from django.conf import settings
from uuid import UUID
from talos.models import Session

class Middleware(object):

    def __init__(self, get_response):
        self.get_response = get_response


    def __call__(self, request):
        header_token = request.META.get('HTTP_AUTHORIZATION', None)
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None) or request.META.get('HTTP_X_SESSION_ID',
                                                                                                  None)
        session_uuid = None

        if session_key:
            try:
                session_uuid = UUID(session_key)
            except:
                pass


        try:
            session = Session.objects.get(uuid=session_uuid)
            principal = session.principal
        except:
            principal = None

        print(principal)

        response = self.get_response(request)
        return response
