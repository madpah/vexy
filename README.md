# Vexy - Generate VEX in CycloneDX

[![shield_gh-workflow-test]][link_gh-workflow-test]
[![shield_rtfd]][link_rtfd]
[![shield_pypi-version]][link_pypi]
[![shield_docker-version]][link_docker]
[![shield_license]][license_file]
[![shield_twitter-follow]][link_twitter]

----

This project provides a runnable Python-based application for generating VEX (Vulnerability Exploitability Exchange) in
CycloneDX format.

This tool is intended to be supplied a [CycloneDX](https://cyclonedx.org/) SBOM file and will produce a separate VEX
which contains known vulnerabilities from a selection of publicly available data sources.

[CycloneDX](https://cyclonedx.org/) is a lightweight BOM specification that is easily created, human-readable, and simple to parse.

Read the full [documentation][link_rtfd] for more details.

## Why?

A SBOM (Software Bill of Materials) is great for cataloging / knowing what components compose a software product.

The same SBOM (in CycloneDX format) can also note _known_ vulnerabilities. What is _known_ is for a given point 
in time - and will change as new vulnerabilities are discovered or disclosed.

CycloneDX allows for separate BOM documents to reference each other through their 
[BOM Link](https://cyclonedx.org/capabilities/bomlink/) capability.

Wouldn't it be great if you could periodically generate a VEX based from your SBOM to keep things up to date, 
without having to generate a fresh SBOM entirely?

That is where **vexy** comes in.

## Installation

Install this from [PyPi.org][link_pypi] using your preferred Python package manager.

Example using `pip`:

```shell
pip install vexy
```

Example using `poetry`:

```shell
poetry add vexy
```

## Usage

## Basic usage

```text
$ vexy --help

usage: vexy [-h] -i FILE_PATH [--format {xml,json}] [--schema-version {1.4}] [-o FILE_PATH] [--force] [-X]

Vexy VEX Generator

options:
  -h, --help            show this help message and exit
  -X                    Enable debug output

Input CycloneDX BOM:
  Where Vexy shall obtain it's input

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

```

### Advanced usage and details

See the full [documentation][link_rtfd] for advanced usage and details on input formats, switches and options.

## Python Support

We endeavour to support all functionality for all [current actively supported Python versions](https://www.python.org/downloads/).
However, some features may not be possible/present in older Python versions due to their lack of support.

## Contributing

Feel free to open issues, bugreports or pull requests.  
See the [CONTRIBUTING][contributing_file] file for details.

## Copyright & License

Vexy is Copyright (c) Paul Horton. All Rights Reserved.  
Permission to modify and redistribute is granted under the terms of the Apache 2.0 license.  
See the [LICENSE][license_file] file for the full license.

[license_file]: https://github.com/madpah/vexy/blob/master/LICENSE
[contributing_file]: https://github.com/madpah/vexy/blob/master/CONTRIBUTING.md
[link_rtfd]: https://vexy.readthedocs.io/

[shield_gh-workflow-test]: https://img.shields.io/github/workflow/status/madpah/vexy/Python%20CI/master?logo=GitHub&logoColor=white "build"
[shield_rtfd]: https://img.shields.io/readthedocs/vexy?logo=readthedocs&logoColor=white
[shield_pypi-version]: https://img.shields.io/pypi/v/vexy?logo=Python&logoColor=white&label=PyPI "PyPI"
[shield_docker-version]: https://img.shields.io/docker/v/madpah/vexy?logo=docker&logoColor=white&label=docker "docker"
[shield_license]: https://img.shields.io/github/license/madpah/vexy?logo=open%20source%20initiative&logoColor=white "license"
[shield_twitter-follow]: https://img.shields.io/badge/Twitter-follow-blue?logo=Twitter&logoColor=white "twitter follow"
[link_gh-workflow-test]: https://github.com/madpah/vexy/actions/workflows/python.yml?query=branch%3Amaster
[link_pypi]: https://pypi.org/project/vexy/
[link_docker]: https://hub.docker.com/r/madpah/vexy
[link_twitter]: https://twitter.com/madpah
