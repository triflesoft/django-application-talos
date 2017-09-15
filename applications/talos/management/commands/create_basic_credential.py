from datetime import datetime
from datetime import timedelta
from ..abstract_command import AbstractModelCommand


class Command(AbstractModelCommand):
    help = 'Creates new basic credential for existing principal.'

    def add_command_arguments(self, parser):
        principal_parser = parser.add_mutually_exclusive_group(required=True)
        principal_parser.add_argument(
            '--principal-id',
            type=int,
            metavar='0',
            help='Integer identifier to select principal by.')
        principal_parser.add_argument(
            '--principal-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID to select principal by.')
        principal_parser.add_argument(
            '--principal-email',
            type=str,
            metavar='"johndoe@example.com"',
            help='Email address to select principal by.')
        principal_parser.add_argument(
            '--principal-phone',
            type=str,
            metavar='"+1-541-754-3010"',
            help='Phone number to select principal by.')

        directory_parser = parser.add_mutually_exclusive_group(required=False)
        directory_parser.add_argument(
            '--directory-id',
            type=int,
            metavar='0',
            help='Integer identifier to select principal by.')
        directory_parser.add_argument(
            '--directory-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID to select principal by.')
        directory_parser.add_argument(
            '--directory-code',
            type=str,
            metavar='"internal"',
            help='Primary contact to select principal by.')

        parser.add_argument(
            '--new-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID of basic credential.')
        parser.add_argument(
            '--new-password',
            type=str,
            metavar='"p@$$W0rD"',
            required=True,
            help='Password.')
        parser.add_argument(
            '--new-valid-from',
            type=str,
            metavar='"{0}"'.format((datetime.now() - timedelta(days=1)).isoformat()),
            help='Date and time credential is valid from.')
        parser.add_argument(
            '--new-valid-till',
            type=str,
            metavar='"{0}"'.format((datetime.now() + timedelta(days=42)).isoformat()),
            help='Date and time credential is valid till.')
        parser.add_argument(
            '--new-algorithm-name',
            type=str,
            metavar='bcrypt|scrypt|pbkdf2',
            required=False,
            help='Algorithm name to use for password encryption.',
            default='pbkdf2')
        parser.add_argument(
            '--new-algorithm-rounds',
            type=str,
            metavar='1000',
            required=False,
            help='Algorithm rounds to use for password encryption.',
            default=100000)
        parser.add_argument(
            '--new-force-change',
            action='store_true',
            help='Force user to change password on first logon.')

    def handle_command(self, *args, **options):
        from ...models import _tzmax
        from ...models import _tzmin
        from ...models import BasicCredential
        from ...models import BasicCredentialDirectory
        from ...models import Principal
        from django.utils.dateparse import parse_datetime
        from uuid import UUID
        from uuid import uuid4

        directory = self.get_object(BasicCredentialDirectory.objects, options, 'directory_', BasicCredentialDirectory.get_auth_directory)
        principal = self.get_object(Principal.objects, options, 'principal_', None)
        basic_credential = BasicCredential()
        basic_credential.uuid = UUID(options['new_uuid']) if options['new_uuid'] else uuid4()
        basic_credential.principal = principal
        basic_credential.valid_from = parse_datetime(options['new_valid_from']) if options['new_valid_from'] else _tzmin()
        basic_credential.valid_till = parse_datetime(options['new_valid_till']) if options['new_valid_till'] else _tzmax()
        basic_credential.directory = directory
        basic_credential.algorithm_name = options['new_algorithm_name']
        basic_credential.algorithm_rounds = int(options['new_algorithm_rounds'])
        basic_credential.force_change = True if options['new_force_change'] else False
        basic_credential.set_password(options['new_password'])
        basic_credential.save()

        return basic_credential
