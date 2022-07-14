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
import sys
from datetime import datetime
from importlib import import_module
from io import TextIOWrapper
from os import getcwd, path
from string import printable
from typing import Dict, Optional, Set, cast
from urllib.parse import quote

import yaml
from cyclonedx.model import ExternalReference, ExternalReferenceType, Tool, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.output import BaseOutput, OutputFormat, SchemaVersion
from rich.console import Console
from rich.progress import Progress

from vexy.parser import BaseParser
from vexy.parser.cyclonedx import CycloneDxJsonParser, CycloneDxXmlParser
from vexy.sources import ALL_SOURCES
from vexy.sources.base import BaseSource


@enum.unique
class _CLI_OUTPUT_FORMAT(enum.Enum):
    XML = 'xml'
    JSON = 'json'


_output_formats: Dict[_CLI_OUTPUT_FORMAT, OutputFormat] = {
    _CLI_OUTPUT_FORMAT.XML: OutputFormat('Xml'),
    _CLI_OUTPUT_FORMAT.JSON: OutputFormat('Json'),
}
_output_default_filenames = {
    _CLI_OUTPUT_FORMAT.XML: 'cyclonedx-vex.xml',
    _CLI_OUTPUT_FORMAT.JSON: 'cyclonedx-vex.json',
}

if sys.version_info >= (3, 8):
    from importlib.metadata import version as meta_version
else:
    from importlib_metadata import version as meta_version

try:
    __ThisToolVersion: Optional[str] = str(meta_version('vexy'))  # type: ignore[no-untyped-call]
except Exception:
    __ThisToolVersion = None
ThisTool = Tool(vendor='Vexy', name='vexy', version=__ThisToolVersion or 'UNKNOWN')
ThisTool.external_references.update([
    ExternalReference(
        reference_type=ExternalReferenceType.BUILD_SYSTEM,
        url=XsUri('https://github.com/madpah/vexy/actions')
    ),
    ExternalReference(
        reference_type=ExternalReferenceType.DISTRIBUTION,
        url=XsUri('https://pypi.org/project/vexy/')
    ),
    ExternalReference(
        reference_type=ExternalReferenceType.DOCUMENTATION,
        url=XsUri('https://vexy.readthedocs.io/')
    ),
    ExternalReference(
        reference_type=ExternalReferenceType.ISSUE_TRACKER,
        url=XsUri('https://github.com/madpah/vexy/issues')
    ),
    ExternalReference(
        reference_type=ExternalReferenceType.LICENSE,
        url=XsUri('https://github.com/madpah/vexy/blob/main/LICENSE')
    ),
    ExternalReference(
        reference_type=ExternalReferenceType.RELEASE_NOTES,
        url=XsUri('https://github.com/madpah/vexy/blob/main/CHANGELOG.md')
    ),
    ExternalReference(
        reference_type=ExternalReferenceType.VCS,
        url=XsUri('https://github.com/madpah/vexy')
    )
])


class VexyCmd:
    DEFAULT_CONFIG_FILE: str = '.vexy.config'

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

        self._data_sources: Set[BaseSource] = set()
        self._attempt_source_config_load(config=self._arguments.vexy_config)

        if not self._is_quiet():
            self._console.print(
                f'Vexy is configured to use [bold cyan]{len(self._data_sources)}[/bold cyan] data sources.'
            )

    def _attempt_source_config_load(self, config: TextIOWrapper) -> None:
        # Attempts to Vexy source configuration at the locations
        with config as config_f:
            vexy_config = yaml.safe_load(config_f.read())
            for source_key, source_config in vexy_config['sources'].items():
                self._data_sources.add(ALL_SOURCES[source_key](config=source_config))

    def get_cli_output_format(self) -> _CLI_OUTPUT_FORMAT:
        return _CLI_OUTPUT_FORMAT(str(self._arguments.output_format).lower())

    def _get_output_format(self) -> OutputFormat:
        return _output_formats[self.get_cli_output_format()]

    def _is_quiet(self) -> bool:
        return bool(self._arguments.quiet_enabled)

    def execute(self) -> None:
        with Progress() as progress:
            task_parse = progress.add_task(
                'Parsing CycloneDX BOM for Components', total=100, visible=not self._is_quiet()
            )
            progress.start_task(task_id=task_parse)

            parser: BaseParser
            if str(self._arguments.input_source.name).endswith('.json'):
                parser = CycloneDxJsonParser(input_file=self._arguments.input_source)
            elif str(self._arguments.input_source.name).endswith('.xml'):
                parser = CycloneDxXmlParser(input_file=self._arguments.input_source)

            parser.parse_bom()
            progress.update(
                task_id=task_parse, completed=100,
                description=f'Parsed {len(parser.bom.components)} Components from CycloneDX SBOM'
            )

            vex = Bom()
            vex.metadata.tools.add(ThisTool)
            data_source_tasks = {}
            for data_source in self._data_sources:
                data_source_tasks[data_source.__class__] = progress.add_task(
                    f'Consulting {data_source.source_name()} for known vulnerabilities', total=100,
                    visible=not self._is_quiet()
                )
                data_source.process_components(components=parser.bom.components)
                progress.update(
                    task_id=data_source_tasks[data_source.__class__], completed=25,
                    description=f'{data_source.source_name()}: Querying for {len(data_source.valid_components)} '
                                f'Components'
                )
                vulnerabilities = data_source.get_vulnerabilities()
                progress.update(
                    task_id=data_source_tasks[data_source.__class__], completed=50,
                    description=f'{data_source.source_name()}: Processing Vulnerabilities for '
                                f'{len(data_source.valid_components)} Components'
                )

                # @todo: CALL OUT ANY COMPONENTS THAT WERE NOT QUERIED

                i: int = 1
                for v in vulnerabilities:
                    for a in v.affects:
                        a.ref = f'{parser.bom.urn()}#{quote(a.ref, safe=printable)}'
                    vex.vulnerabilities.add(v)
                    progress.update(
                        task_id=data_source_tasks[data_source.__class__],
                        completed=(50 + (i / len(vulnerabilities) * 50))
                    )
                    i += 1

        output_format = self._get_output_format()
        outputter = self._get_outputter(output_format=output_format, bom=vex)

        if self._arguments.output_file == '-' or not self._arguments.output_file:
            self._debug_message('Returning SBOM to STDOUT')
            print(outputter.output_as_string())
            return

        # Check directory writable
        output_file = self._arguments.output_file
        output_filename = path.realpath(
            output_file if isinstance(output_file, str) else _output_default_filenames[self.get_cli_output_format()]
        )
        self._debug_message('Will be outputting SBOM to file at: {}'.format(output_filename))
        outputter.output_to_file(filename=output_filename, allow_overwrite=self._arguments.output_file_overwrite)

    def _get_outputter(self, output_format: OutputFormat, bom: Bom) -> BaseOutput:
        schema_version = SchemaVersion['V{}'.format(
            str(self._arguments.output_schema_version).replace('.', '_')
        )]
        try:
            module = import_module(f"cyclonedx.output.{self._arguments.output_format.lower()}")
            output_klass = getattr(module, f"{output_format.value}{schema_version.value}")
        except (ImportError, AttributeError):
            raise ValueError(f"Unknown format {output_format.value.lower()!r}") from None

        return cast(BaseOutput, output_klass(bom=bom))

    @staticmethod
    def get_arg_parser(*, prog: Optional[str] = None) -> argparse.ArgumentParser:
        arg_parser = argparse.ArgumentParser(prog=prog, description='Vexy VEX Generator')

        arg_parser.add_argument(
            '-c', '--config', action='store', type=argparse.FileType('r'),  # FileType does handle '-'
            dest='vexy_config', required=True, default=f'{getcwd()}/{VexyCmd.DEFAULT_CONFIG_FILE}',
            help='Configuration file for Vexy defining data sources to use and their configuration.'
        )
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
