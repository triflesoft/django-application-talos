from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import *
from talos.models import BasicIdentityDirectoryOption

basic_identity_directory_option = BasicIdentityDirectoryOption.objects.filter(
    directory__code='ldap')


class LdapConnection():

    def __init__(self):
        needful_items = ['host', 'username', 'password', 'port', 'search_base']
        values = {}

        for item in needful_items:
            try:
                queryset = basic_identity_directory_option.get(name=item)
                values[item] = queryset.value
            except BasicIdentityDirectoryOption.DoesNotExist:
                raise BasicIdentityDirectoryOption.DoesNotExist(
                    'Please specify ldap {item} in BasicIdentityDirectoryOption'.format(item=item))

        self.host = values['host']
        self.port = int(values['port'])
        self.username = values['username']
        self.password = values['password']
        self.search_base = values['search_base']

        self.server = self.server_connect()
        self.connection = self.create_connection()

    def server_connect(self):
        server = Server(self.host, port=self.port, get_info=ALL)
        if not server.check_availability():
            raise Exception('LDAP Server is not reachable')
        return server

    def create_connection(self):
        if not self.server:
            raise Exception("Please run connect()")
        connection = Connection(self.server, user=self.username, password=self.password,
                                check_names=True,
                                lazy=False, raise_exceptions=True)
        connection.open()

        try:
            connection.bind()
        except LDAPInvalidCredentialsResult:
            raise LDAPInvalidCredentialsResult("Invalid LDAP Credentials")

        return connection

    def check_credentials(self, username, password):
        if '@' in username:
            search_filter = "userPrincipalName"
        elif "\\" in username:
            search_filter = "sAMAccountName"
            username = username.split('\\')[1]
        else:
            search_filter = "sAMAccountName"

        self.connection.search(search_base=self.search_base,
                               search_filter='({search_filter}={username})'.format(
                                   search_filter=search_filter,
                                   username=username),
                               attributes=['*'], get_operational_attributes = True
                               )
        print(self.connection.entries)
        userPrincipalName = str(self.connection.entries[0]['userPrincipalName'])
        print(userPrincipalName)

        self.connection = Connection(self.server, user=userPrincipalName, password=password,
                                     check_names=True,
                                     lazy=False, raise_exceptions=True, auto_bind=True)
        self.connection.open()
        try:
            self.connection.bind()
        except LDAPInvalidCredentialsResult:
            raise LDAPInvalidCredentialsResult("Invalid credentials")
        return True
