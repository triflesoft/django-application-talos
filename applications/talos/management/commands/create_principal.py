from ..abstract_command import AbstractModelCommand


class Command(AbstractModelCommand):
    help = 'Creates new principal.'

    def add_command_arguments(self, parser):
        parser.add_argument(
            '--new-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID of principal. Will be generated if not specified.')
        parser.add_argument(
            '--new-brief-name',
            type=str,
            metavar='John',
            help='Brief name of principal.')
        parser.add_argument(
            '--new-full-name',
            type=str,
            metavar='"John Doe"',
            help='Full name of principal.')
        parser.add_argument(
            '--new-email',
            type=str,
            metavar='"johndoe@example.com"',
            required=True,
            help='Email address of principal.')
        parser.add_argument(
            '--new-phone',
            type=str,
            metavar='"+1-541-754-3010"',
            required=False,
            help='Phone number of principal.')

        status_parser = parser.add_mutually_exclusive_group(required=True)
        status_parser.add_argument('--new-active', action='store_true', dest='new_is_active', help='Activate principal.')
        status_parser.add_argument('--new-passive', action='store_false', dest='new_is_active', help='Disactivate principal.')

    def handle_command(self, *args, **options):
        from ...models import Principal
        from uuid import UUID
        from uuid import uuid4

        principal = Principal()
        principal.uuid = UUID(options['new_uuid']) if options['new_uuid'] else uuid4()
        principal.brief_name = options['new_brief_name']
        principal.full_name = options['new_full_name']
        principal.email = options['new_email']
        principal.phone = options['new_phone'] if options['new_phone'] else None
        principal.is_active = options['new_is_active']
        principal.save()

        return principal
