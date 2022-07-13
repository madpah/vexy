..  # This file is part of Vexy
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

Usage
============

``vexy`` is designed to be run as a standalone application.

Once installed, you can call the tool via the following methods:

.. code-block:: bash

    $ python3 -m vexy
    $ vexy

The full documentation can be issued by running with ``--help``:

.. code-block::

    $ vexy --help
    usage: vexy [-h] -c VEXY_CONFIG [-q] [-X] -i FILE_PATH [--format {xml,json}] [--schema-version {1.4}] [-o FILE_PATH] [--force]

    Vexy VEX Generator

    options:
      -h, --help            show this help message and exit
      -c VEXY_CONFIG, --config VEXY_CONFIG
                            Configuration file for Vexy defining data sources to use and their configuration.
      -q                    Quiet - no console output
      -X                    Enable debug output

    Input CycloneDX BOM:
      Where Vexy shall obtain its input

      -i FILE_PATH, --in-file FILE_PATH
                            CycloneDX BOM to read input from. Use "-" to read from STDIN.

    VEX Output Configuration:
      Choose the output format and schema version

      --format {xml,json}   The output format for your SBOM (default: xml)
      --schema-version {1.4}
                            The CycloneDX schema version for your VEX (default: 1.4)
      -o FILE_PATH, --o FILE_PATH, --output FILE_PATH
                            Output file path for your SBOM (set to '-' to output to STDOUT)
      --force               If outputting to a file and the stated file already exists, it will be overwritten.