import json

from django.core.management.base import BaseCommand, CommandError

from common.sdk.gm.piico import (
    format_piico_self_test_report_lines,
    run_piico_self_test,
)


class Command(BaseCommand):
    help = "Check Piico device health"

    def add_arguments(self, parser):
        parser.add_argument(
            "--driver-path",
            default=None,
            help="Override PIICO driver path",
        )
        parser.add_argument(
            "--tests",
            default=None,
            help="Comma-separated self-test names, for example: random,sm3,sm4_ecb",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Print structured JSON result",
        )

    def handle(self, *args, **options):
        test_names = None
        if options["tests"]:
            test_names = tuple(
                name.strip() for name in options["tests"].split(",") if name.strip()
            )

        if not options["json"]:
            self.stdout.write("加密模块开始自检")

        result = run_piico_self_test(
            driver_path=options["driver_path"],
            test_names=test_names,
        )

        if options["json"]:
            self.stdout.write(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            for line in format_piico_self_test_report_lines(result):
                self.stdout.write(line)

        if not result.get("ok"):
            raise CommandError("Piico self-test failed")
