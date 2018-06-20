from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, \
    BASE, LEVEL, DEREF_NEVER, DEREF_SEARCH, DEREF_BASE, DEREF_ALWAYS
from ldap3.core.exceptions import *
from talos.models import BasicIdentityDirectoryOption

basic_identity_directory_option = BasicIdentityDirectoryOption.objects.filter(
    directory__code='ldap')


class LdapConnection():

    def __init__(self):
        needful_items = ['host', 'username', 'password', 'port', 'user_search_base','cn_search_base']
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
        self.user_search_base = values['user_search_base']
        self.cn_search_base = values['cn_search_base']

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
                                raise_exceptions=True)
        connection.open()

        try:
            connection.bind()

        except LDAPInvalidCredentialsResult:

            raise LDAPAttributeError("Invalid LDAP Credentials")

        return connection

    def check_credentials(self, username, password):
        # If user principal name is entered (example@server.com)
        if '@' in username:
            search_filter = "userPrincipalName"
            search_value = username

        # If user NetBios\sAMAccountName is entered
        elif "\\" in username:
            net_bios_name = username.split('\\')[0]
            username = username.split('\\')[1]

            self.connection.search(search_base=self.cn_search_base,
                                   search_filter='(netbiosname=*)',
                                   attributes=['*']
                                   )
            net_bios_name_entries = self.connection.entries

            if len(net_bios_name_entries) == 0:
                raise LDAPAttributeError("NetBos name not found")

            # If user input netbios name match netbios name searched in LDAP
            elif net_bios_name != self.connection.entries[0]['nETBIOSName']:
                raise LDAPInvalidCredentialsResult("Invalid NetBios name")

            # If dc=server, dc=com is matched to read domain controller
            elif self.user_search_base != self.connection.entries[0]['nCName']:
                raise LDAPInvalidCredentialsResult("Invalid NetBios name")

            search_value = username
            search_filter = "sAMAccountName"

        else:
            search_value = username
            search_filter = "sAMAccountName"

        self.connection.search(search_base=self.user_search_base,
                               search_filter='({search_filter}={search_value})'.format(
                                   search_filter=search_filter,
                                   search_value=search_value),
                               attributes='userPrincipalName'
                               )
        # If no user found
        if len(self.connection.entries) != 1:
            raise LDAPInvalidCredentialsResult('Username not found in LDAP')

        userPrincipalName = str(self.connection.entries[0]['userPrincipalName'])

        self.connection = Connection(self.server, user=userPrincipalName, password=password,
                                     check_names=True,
                                     lazy=False, raise_exceptions=True, auto_bind=True)
        self.connection.open()

        try:
            self.connection.bind()
        except LDAPInvalidCredentialsResult:
            raise LDAPInvalidCredentialsResult("Invalid credentials")

        return True
