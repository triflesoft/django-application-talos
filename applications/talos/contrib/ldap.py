from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import *
from django.conf   import settings

class LdapConnection():
    host = settings.LDAP_HOST

    def __init__(self, host=host, port=389):
        self.host = host
        self.port = port
        self.server = None

    def connect(self):
        self.server = Server(self.host, port=self.port, get_info=ALL)
        if not self.server.check_availability():
            raise Exception('LDAP Server is not reachable')

        return self.server

    def check_credentials(self, email, password):
        if not self.server:
            raise Exception("Please run connect()")

        self.connection = Connection(self.server, user=email, password=password, check_names=True,
                                     lazy=False, raise_exceptions=True)
        self.connection.open()
        try:
            self.connection.bind()
        except LDAPInvalidCredentialsResult:
            raise LDAPInvalidCredentialsResult("Invalid credentials")
        return True


