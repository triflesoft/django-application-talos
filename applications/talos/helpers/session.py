from django.http.request import HttpRequest

def request_principal_get(self):
    return getattr(self, '_principal', None)

def request_principal_set(self, value):
    setattr(self, '_principal', value)

def request_principal_del(self):
    delattr(self, '_principal')


request_principal_property = property(request_principal_get, request_principal_set, request_principal_del)

HttpRequest.user = request_principal_property
HttpRequest.principal = request_principal_property


class Context(object):
    TEST_COOKIE_NAME = 'cbcf165cfa4e4e30b2e5fe0e9d4fac6d'
    TEST_COOKIE_VALUE = 'c7446479a81643f59314999b2c34ba7b'

    def _parse_user_agent(self, user_agent):
        try:
            from ua_parser import user_agent_parser

            user_agent = user_agent_parser.Parse(user_agent)
            remote_hw_family = '-'
            remote_hw_model = '-'

            if 'device' in user_agent:
                user_agent_device = user_agent.get('device')
                user_agent_device_brand = user_agent_device.get('brand', None)
                user_agent_device_family = user_agent_device.get('family', None)
                user_agent_device_model = user_agent_device.get('model', None)

                if user_agent_device_brand:
                    remote_hw_family = user_agent_device_brand

                    if user_agent_device_family:
                        if user_agent_device_model and (user_agent_device_family != user_agent_device_model):
                            remote_hw_model = '{0}, {1}'.format(user_agent_device_family, user_agent_device_model)
                        else:
                            remote_hw_model = '{0}'.format(user_agent_device_family)

            remote_os_family = '-'
            remote_os_version = '-'

            if 'os' in user_agent:
                user_agent_os = user_agent.get('os')
                user_agent_os_family = user_agent_os.get('family', None)
                user_agent_os_major = user_agent_os.get('major', None)
                user_agent_os_minor = user_agent_os.get('minor', None)

                if user_agent_os_family:
                    remote_os_family = user_agent_os_family

                    if user_agent_os_major:
                        if user_agent_os_minor:
                            remote_os_version = '{0}.{1}'.format(user_agent_os_major, user_agent_os_minor)
                        else:
                            remote_os_version = user_agent_os_major

            remote_ua_family = '-'
            remote_ua_version = '-'

            if 'user_agent' in user_agent:
                user_agent_ua = user_agent.get('user_agent')
                user_agent_ua_family = user_agent_ua.get('family', None)
                user_agent_ua_major = user_agent_ua.get('major', None)
                user_agent_ua_minor = user_agent_ua.get('minor', None)

                if user_agent_ua_family:
                    remote_ua_family = user_agent_ua_family

                    if user_agent_ua_major:
                        if user_agent_ua_minor:
                            remote_ua_version = '{0}.{1}'.format(user_agent_ua_major, user_agent_ua_minor)
                        else:
                            remote_ua_version = user_agent_ua_major

            return remote_hw_family, remote_hw_model, remote_os_family, remote_os_version, remote_ua_family, remote_ua_version
        except:
            return '', '', '', '', user_agent, ''

    def _new_session(self):
        from ..models import Session

        address = self.request.META.get('REMOTE_ADDR', '')
        geoname = self.request.META.get(self._geoname_header_name, '')
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        remote_hw_family, remote_hw_model, remote_os_family, remote_os_version, remote_ua_family, remote_ua_version = self._parse_user_agent(user_agent)

        self._session = Session(
            previous_session=self._session,
            remote_address=address,
            remote_geoname=geoname,
            remote_hw_family=remote_hw_family,
            remote_hw_model=remote_hw_model,
            remote_os_family=remote_os_family,
            remote_os_version=remote_os_version,
            remote_ua_family=remote_ua_family,
            remote_ua_version=remote_ua_version)

    def _get_session(self, now, uuid):
        from ..models import Session

        address = self.request.META.get('REMOTE_ADDR', '')
        geoname = self.request.META.get(self._geoname_header_name, '')
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        remote_hw_family, remote_hw_model, remote_os_family, remote_os_version, remote_ua_family, remote_ua_version = self._parse_user_agent(user_agent)

        try:
            self._session = Session.objects.get(
                uuid=uuid,
                valid_from__lte=now,
                valid_till__gte=now,
                remote_geoname=geoname,
                remote_hw_family=remote_hw_family,
                remote_os_family=remote_os_family,
                remote_ua_family=remote_ua_family)
            self._session.remote_hw_model = remote_hw_model
            self._session.remote_os_version = remote_os_version
            self._session.remote_ua_version = remote_ua_version
        except Session.DoesNotExist:
            self._session = Session(
                previous_session=self._session,
                remote_address=address,
                remote_geoname=geoname,
                remote_hw_family=remote_hw_family,
                remote_hw_model=remote_hw_model,
                remote_os_family=remote_os_family,
                remote_os_version=remote_os_version,
                remote_ua_family=remote_ua_family,
                remote_ua_version=remote_ua_version)

    def __init__(self, request):
        from django.conf import settings
        from ..models import Principal

        self._session = None
        self._variables = {}
        self._geoname_header_name = getattr(settings, 'TALOS_GEONAME_HEADER', '')
        self.request = request
        self.request.session = self
        self.principal = Principal.objects.get(id=0)
        self.principal._load_authentication_context([])

    def init(self):
        self._new_session()
        self.request.principal = self.principal

    def load(self, uuid):
        from ..models import _tznow
        from ..models import Principal
        from json import loads

        now = _tznow()
        self._get_session(now, uuid)
        self._variables = loads(self._session.variables) if self._session.variables else {}

        if self._session.principal:
            self.principal = self._session.principal
            self.principal._inject_authentication_context(
                self._session.evidences,
                self._session.roles,
                self._session.privileges,
                self._session.model_actions)

        authentication_period = (now - self._session.valid_from).total_seconds()
        valid_evidences = []

        for evidence in self.principal._evidences_effective.values():
            if authentication_period < evidence.expiration_period:
                valid_evidences.append(evidence)

        if len(valid_evidences) != len(self.principal._evidences_effective):
            if len(valid_evidences) == 0:
                self.principal = Principal.objects.get(id=0)

            self.principal._load_authentication_context(valid_evidences)
            self._session.valid_from = now

        self.request.principal = self.principal

    def save(self):
        from ..models import Principal
        from django.utils.functional import LazyObject
        from json import dumps

        self._session.evidences = ''
        self._session.roles = ''
        self._session.privileges = ''
        self._session.model_actions = ''
        self._session.variables = dumps(self._variables)

        if self.request.principal and self.request.principal.is_authenticated:
            if issubclass(type(self.request.principal), LazyObject):
                self.request.principal._setup()

                if type(self.request.principal._wrapped) == Principal:
                    self._session.principal = self.request.principal._wrapped
            elif type(self.request.principal) == Principal:
                self._session.principal = self.request.principal

            if self._session.principal:
                self._session.evidences, \
                    self._session.roles, \
                    self._session.privileges, \
                    self._session.model_actions = self._session.principal._extract_authentication_context()

        self._session.save()

    def get(self, key, default=None):
        return self._variables.get(key, default)

    def pop(self, key, default=None):
        if key in self._variables:
            return self._variables.pop(key, default)

        return None

    def setdefault(self, key, default=None):
        if key in self._variables:
            return self._variables[key]
        else:
            self._variables[key] = default

            return default

    def set_test_cookie(self):
        self[self.TEST_COOKIE_NAME] = self.TEST_COOKIE_VALUE

    def test_cookie_worked(self):
        return self.get(self.TEST_COOKIE_NAME) == self.TEST_COOKIE_VALUE

    def delete_test_cookie(self):
        del self[self.TEST_COOKIE_NAME]

    def update(self, other):
        self._variables.update(other)

    def has_key(self, key):
        return key in self.__store

    def keys(self):
        return self._variables.keys()

    def values(self):
        return self._variables.values()

    def items(self):
        return self._variables.items()

    def iterkeys(self):
        return self._variables.iterkeys()

    def itervalues(self):
        return self._variables.itervalues()

    def iteritems(self):
        return self._variables.iteritems()

    def clear(self):
        self._variables = {}

    def is_empty(self):
        try:
            return len(self._variables) == 0
        except AttributeError:
            return True

    def flush(self):
        from ..models import _tznow
        from ..models import Principal

        if self._session:
            self._session.valid_till = _tznow()
            self._session.save()
            self._new_session()
            self.principal = Principal.objects.get(id=0)
            self.principal._load_authentication_context([])
            self.request.principal = self.principal

    def cycle_key(self):
        if self._session:
            from uuid import uuid4

            self._session.uuid = uuid4()

    def __contains__(self, key):
        return key in self._variables

    def __getitem__(self, key):
        return self._variables[key]

    def __setitem__(self, key, value):
        if key not in ('_auth_user_backend', '_auth_user_hash', '_auth_user_id'):
            self._variables[key] = value

    def __delitem__(self, key):
        del self._variables[key]

    @property
    def uuid(self):
        return self._session.uuid
