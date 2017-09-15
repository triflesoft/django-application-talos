from django.core.management.base import BaseCommand


class AbstractModelCommand(BaseCommand):
    def add_arguments(self, parser):
        self.add_command_arguments(parser)
        parser.add_argument('--output-status', action='store_true', help='Output operation status.')

    def get_object(self, queryset, options, prefix, default_factory):
        for k, v in options.items():
            if (v is not None) and k.startswith(prefix):
                kwargs = {k[len(prefix):]: v}

                return queryset.get(**kwargs)

        return default_factory()

    def handle(self, *args, **options):
        try:
            obj = self.handle_command(*args, **options)

            if options['output_status']:
                self.stdout.write(self.style.SUCCESS('SUCCESS; type="{0}"; id="{1}"; uuid="{2}".'.format(type(obj).__name__, obj.id, obj.uuid)))
        except:
            if options['output_status']:
                self.stdout.write(self.style.ERROR('ERROR; type="?"; id="0"; uuid="{00000000-0000-0000-0000-000000000000}"'))

            raise
