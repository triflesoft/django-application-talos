from ..abstract_command import AbstractModelCommand


class Command(AbstractModelCommand):
    help = 'Updates existing role.'

    def add_command_arguments(self, parser):
        filter_parser = parser.add_mutually_exclusive_group(required=True)
        filter_parser.add_argument(
            '--role-id',
            type=int,
            metavar='0',
            help='Integer identifier to select role by.')
        filter_parser.add_argument(
            '--role-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID to select role by.')
        filter_parser.add_argument(
            '--role-code',
            type=str,
            metavar='users',
            help='Code to select role by.')

        parser.add_argument(
            '--new-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID of role. Will be generated if not specified.')
        parser.add_argument(
            '--new-code',
            type=str,
            metavar='users',
            required=True,
            help='Code of role.')
        parser.add_argument(
            '--new-name',
            type=str,
            metavar='"Users"',
            required=True,
            help='Name of role.')

        status_parser = parser.add_mutually_exclusive_group(required=False)
        status_parser.add_argument(
            '--new-parent-id',
            type=int,
            metavar='0',
            help='Integer identifier of parent role if any.')
        status_parser.add_argument(
            '--new-parent-uuid',
            type=str,
            metavar='"{00000000-0000-0000-0000-000000000000}"',
            help='UUID of parent role if any.')
        status_parser.add_argument(
            '--new-parent-code',
            type=str,
            metavar='"everybody"',
            help='Code of parent role if any.')

    def handle_command(self, *args, **options):
        from ...models import Role
        from uuid import UUID

        role = self.get_object(Role.objects, options, 'role_', None)

        if not options['new_uuid'] is None:
            role.uuid = UUID(options['new_uuid'])

        if not options['new_code'] is None:
            role.code = UUID(options['new_code'])

        if not options['new_name'] is None:
            role.name = UUID(options['new_name'])

        if not options['new_parent_id'] is None:
            role.parent_role = Role.objects.get(id=int(options['new_parent_id']))

        if not options['new_parent_uuid'] is None:
            role.parent_role = Role.objects.get(uuid=UUID(options['new_parent_uuid']))

        if not options['new_parent_code'] is None:
            role.parent_role = Role.objects.get(code=UUID(options['new_parent_code']))

        role.save()

        return role
