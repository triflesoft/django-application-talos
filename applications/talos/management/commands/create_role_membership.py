from ..abstract_command import AbstractModelCommand


class Command(AbstractModelCommand):
    help = 'Creates membership of principal in role.'

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

        role_parser = parser.add_mutually_exclusive_group(required=True)
        role_parser.add_argument(
            '--role-id',
            type=int,
            metavar='0',
            help='Integer identifier to select role by.')
        role_parser.add_argument(
            '--role-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID to select role by.')
        role_parser.add_argument(
            '--role-code',
            type=str,
            metavar='administrators',
            help='Code to select role by.')

        parser.add_argument(
            '--new-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID of membership.')

    def handle_command(self, *args, **options):
        from ...models import Principal
        from ...models import PrincipalRoleMembership
        from ...models import Role
        from uuid import UUID
        from uuid import uuid4

        role = self.get_object(Role.objects, options, 'role_', None)
        principal = self.get_object(Principal.objects, options, 'principal_', None)
        principal_role_membership = PrincipalRoleMembership()
        principal_role_membership.uuid = UUID(options['new_uuid']) if options['new_uuid'] else uuid4()
        principal_role_membership.principal = principal
        principal_role_membership.role = role
        principal_role_membership.save()

        return principal_role_membership
