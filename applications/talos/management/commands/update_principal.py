from ..abstract_command import AbstractModelCommand


class Command(AbstractModelCommand):
    help = 'Updates existing principal.'

    def add_command_arguments(self, parser):
        filter_parser = parser.add_mutually_exclusive_group(required=True)
        filter_parser.add_argument(
            '--principal-id',
            type=int,
            metavar='0',
            help='Integer identifier to select principal by.')
        filter_parser.add_argument(
            '--principal-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID to select principal by.')
        filter_parser.add_argument(
            '--principal-email',
            type=str,
            metavar='"johndoe@example.com"',
            help='Email address to select principal by.')
        filter_parser.add_argument(
            '--principal-phone',
            type=str,
            metavar='"+1-541-754-3010"',
            help='Phone number to select principal by.')

        parser.add_argument(
            '--new-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID of principal.')
        parser.add_argument(
            '--new-brief-name',
            type=str,
            metavar='John',
            help='Brief name of principal to update to.')
        parser.add_argument(
            '--new-full-name',
            type=str,
            metavar='"John Doe"',
            help='Full name of principal to update to.')
        parser.add_argument(
            '--new-email',
            type=str,
            metavar='"johndoe@example.com"',
            required=True,
            help='Email address of principal to update to.')
        parser.add_argument(
            '--new-phone',
            type=str,
            metavar='"+1-541-754-3010"',
            required=False,
            help='Phone number of principal to update to.')

        status_parser = parser.add_mutually_exclusive_group(required=False)
        status_parser.add_argument('--new-active', action='store_true', dest='new_is_active', help='Activate principal.')
        status_parser.add_argument('--new-passive', action='store_false', dest='new_is_active', help='Disactivate principal.')

    def handle_command(self, *args, **options):
        from ...models import Principal
        from uuid import UUID

        principal = self.get_object(Principal.objects, options, 'principal_', None)

        if not options['new_uuid'] is None:
            principal.uuid = UUID(options['new_uuid'])

        if not options['new_brief_name'] is None:
            principal.brief_name = options['brief_name']

        if not options['new_full_name'] is None:
            principal.full_name = options['full_name']

        if not options['new_email'] is None:
            principal.primary_contact = options['email']

        if not options['new_phone'] is None:
            principal.primary_contact = options['phone']

        if not options['new_is_active'] is None:
            principal.is_active = options['new_is_active']

        principal.save()

        return principal
