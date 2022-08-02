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

import enum


class EcoSystemType:

    def __init__(self, *, name: str, purl_type: str, description: str) -> None:
        self._name = name
        self._purl_type = purl_type
        self._description = description

    @property
    def name(self) -> str:
        return self._name

    @property
    def purl_type(self) -> str:
        return self._purl_type

    @property
    def description(self) -> str:
        return self._description


_ALL_ECOSYSTEMS = {
    'CARGO': EcoSystemType(
        name='Cargo', purl_type='cargo', description='The Rust community\'s crate registry'
    ),
    'COCOAPODS': EcoSystemType(
        name='Cocoapods', purl_type='cocoapods', description='The Cocoa dependency manager'
    ),
    'COMPOSER': EcoSystemType(
        name='Composer', purl_type='composer', description='Dependency Manager for PHP'
    ),
    'CONAN': EcoSystemType(
        name='Conan', purl_type='conan', description='The open-source C/C++ package manager'
    ),
    'CONDA': EcoSystemType(
        name='Conda', purl_type='conda', description='Conda is a cross-platform, language-agnostic binary package '
                                                     'manager'
    ),
    'CRAN': EcoSystemType(
        name='Cran', purl_type='cran', description='Comprehensive R Archive Network'
    ),
    'GO': EcoSystemType(
        name='Go', purl_type='golang', description='Go Package Managers'
    ),
    'MAVEN': EcoSystemType(
        name='Maven', purl_type='maven', description='Apache Maven'
    ),
    'NPM': EcoSystemType(
        name='NPM', purl_type='npm', description='Package manager for the JavaScript programming language'
    ),
    'NUGET': EcoSystemType(
        name='NuGet', purl_type='nuget', description='Microsoft NuGet'
    ),
    'PYPI': EcoSystemType(
        name='PyPi', purl_type='pypi', description='Python Package Index'
    ),
    'RPM': EcoSystemType(
        name='RPM', purl_type='rpm', description='Redhat Package Manager'
    ),
    'RUBY_GEM': EcoSystemType(
        name='RubyGems', purl_type='gem', description='Ruby package system'
    ),
    'SWIFT': EcoSystemType(
        name='Swift', purl_type='swift', description='Swift Package Manager'
    )
}


class EcoSystem(enum.Enum):
    """
    Languages/ecosystems to the PURL type

    Starting list taken from https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
    """

    BITBUCKET = 'BITBUCKET'
    CARGO = 'CARGO'
    COCOAPODS = 'COCOAPODS'
    COMPOSER = 'COMPOSER'
    CONAN = 'CONAN'
    CONDA = 'CONDA'
    CRAN = 'CRAN'
    DART = 'PUB'
    DEBIAN = 'DEB'
    DOCKER = 'DOCKER'
    FLUTTER = 'PUB'
    GENERIC = 'GENERIC'
    GITHUB = 'GITHUB'
    GO = 'GOLANG'
    HASKELL = 'HACKAGE'
    HEX = 'HEX'
    MAVEN = 'MAVEN'
    NPM = 'NPM'
    NUGET = 'NUGET'
    OCI = 'OCI'
    PYPI = 'PYPI'
    RPM = 'RPM'
    RUBY_GEM = 'GEM'
    SWIFT = 'SWIFT'

    def get_info(self) -> EcoSystemType:
        return _ALL_ECOSYSTEMS[self.value]
