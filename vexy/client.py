#!/usr/bin/env python
# encoding: utf-8

# This file is part of Vexy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Paul Horton. All Rights Reserved.

import argparse
import enum
from datetime import datetime
from typing import Optional

from cyclonedx.model.bom import Bom
from cyclonedx.output import OutputFormat
from rich.console import Console
from rich.progress import Progress

from vexy.parser.cyclonedx import CycloneDxJsonParser
from vexy.sources import ALL_SOURCES


@enum.unique
class _CLI_OUTPUT_FORMAT(enum.Enum):
    XML = 'xml'
    JSON = 'json'


_output_formats = {
    _CLI_OUTPUT_FORMAT.XML: OutputFormat.XML,
    _CLI_OUTPUT_FORMAT.JSON: OutputFormat.JSON,
}
_output_default_filenames = {
    _CLI_OUTPUT_FORMAT.XML: 'cyclonedx-vex.xml',
    _CLI_OUTPUT_FORMAT.JSON: 'cyclonedx-vex.json',
}


class VexyCmd:
    # Whether debug output is enabled
    _DEBUG_ENABLED: bool = False

    # Parsed Arguments
    _arguments: argparse.Namespace

    def __init__(self, args: argparse.Namespace) -> None:
        self._arguments = args
        self._console = Console()

        if self._arguments.debug_enabled:
            self._DEBUG_ENABLED = True
            self._arguments.quiet_enabled = False
            self._debug_message('!!! DEBUG MODE ENABLED !!!')
            self._debug_message('Parsed Arguments: {}'.format(self._arguments))

    def _get_output_format(self) -> _CLI_OUTPUT_FORMAT:
        return _CLI_OUTPUT_FORMAT(str(self._arguments.output_format).lower())

    def _is_quiet(self) -> bool:
        return bool(self._arguments.quiet_enabled)

    def execute(self) -> None:
        with Progress() as progress:
            task_parse = progress.add_task(
                'Parsing CycloneDX BOM for Components', total=100, visible=not self._is_quiet()
            )
            progress.start_task(task_id=task_parse)

            parser = CycloneDxJsonParser(input_file=self._arguments.input_source)
            parser.parse_bom()
            progress.update(
                task_id=task_parse, completed=100,
                description=f'Parsed {len(parser.bom.components)} Components from CycloneDX SBOM'
            )

            vex = Bom()
            data_source_tasks = {}
            for ds_klass in ALL_SOURCES:
                data_source = ds_klass(components=parser.bom.components)
                data_source_tasks[ds_klass] = progress.add_task(
                    f'Consulting {data_source.source_name()} for known vulnerabilities', total=100,
                    visible=not self._is_quiet()
                )
                progress.update(
                    task_id=data_source_tasks[ds_klass],
                    description=f'{data_source.source_name()}: Querying for {len(data_source.valid_components)} '
                                f'Components'
                )
                vulnerabilities = data_source.get_vulnerabilities()
                progress.update(
                    task_id=data_source_tasks[ds_klass], total=90,
                    description=f'{data_source.source_name()}: Processing Vulnerabilities for '
                                f'{len(data_source.valid_components)} Components'
                )

                # @todo: CALL OUT ANY COMPONENTS THAT WERE NOT QUERIED

                for v in  vulnerabilities:
                    pass

    @staticmethod
    def get_arg_parser(*, prog: Optional[str] = None) -> argparse.ArgumentParser:
        arg_parser = argparse.ArgumentParser(prog=prog, description='Vexy VEX Generator')

        arg_parser.add_argument('-q', action='store_true', help='Quiet - no console output', dest='quiet_enabled')
        arg_parser.add_argument('-X', action='store_true', help='Enable debug output', dest='debug_enabled')

        input_method_group = arg_parser.add_argument_group(
            title='Input CycloneDX BOM',
            description='Where Vexy shall obtain it\'s input'
        )
        input_method_group.add_argument(
            '-i', '--in-file', action='store', metavar='FILE_PATH',
            type=argparse.FileType('r'),  # FileType does handle '-'
            default=None, dest='input_source', required=True,
            help='CycloneDX BOM to read input from. Use "-" to read from STDIN.'
        )

        output_group = arg_parser.add_argument_group(
            title='VEX Output Configuration',
            description='Choose the output format and schema version'
        )
        output_group.add_argument(
            '--format', action='store',
            choices=[f.value for f in _CLI_OUTPUT_FORMAT], default=_CLI_OUTPUT_FORMAT.XML.value,
            help='The output format for your SBOM (default: %(default)s)',
            dest='output_format'
        )
        output_group.add_argument(
            '--schema-version', action='store', choices=['1.4'], default='1.4',
            help='The CycloneDX schema version for your VEX (default: %(default)s)',
            dest='output_schema_version'
        )
        output_group.add_argument(
            '-o', '--o', '--output', action='store', metavar='FILE_PATH', default=True, required=False,
            help='Output file path for your SBOM (set to \'-\' to output to STDOUT)', dest='output_file'
        )
        output_group.add_argument(
            '--force', action='store_true', dest='output_file_overwrite',
            help='If outputting to a file and the stated file already exists, it will be overwritten.'
        )

        return arg_parser

    def _debug_message(self, message: str) -> None:
        if self._DEBUG_ENABLED:
            print('[DEBUG] - {} - {}'.format(datetime.now(), message))

    @staticmethod
    def _error_and_exit(message: str, exit_code: int = 1) -> None:
        print('[ERROR] - {} - {}'.format(datetime.now(), message))
        exit(exit_code)


def main(*, prog_name: Optional[str] = None) -> None:
    parser = VexyCmd.get_arg_parser(prog=prog_name)
    args = parser.parse_args()
    VexyCmd(args).execute()


if __name__ == "__main__":
    main()
