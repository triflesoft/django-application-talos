from ..abstract_command import AbstractModelCommand


class Command(AbstractModelCommand):
    help = 'Creates new basic identity for existing principal.'

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
            '--new-username',
            type=str,
            metavar='j.doe',
            required=True,
            help='Unique username.')

    def handle_command(self, *args, **options):
        from ...models import BasicIdentity
        from ...models import BasicIdentityDirectory
        from ...models import Principal
        from uuid import UUID
        from uuid import uuid4

        directory = self.get_object(BasicIdentityDirectory.objects, options, 'directory_', BasicIdentityDirectory.get_auth_directory)
        principal = self.get_object(Principal.objects, options, 'principal_', None)

        basic_identity = BasicIdentity()
        basic_identity.uuid = UUID(options['new_uuid']) if options['new_uuid'] else uuid4()
        basic_identity.principal = principal
        basic_identity.directory = directory
        basic_identity.username = options['new_username'].strip()
        basic_identity.save()

        return basic_identity
