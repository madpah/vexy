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

from abc import ABC, abstractmethod
from io import TextIOWrapper

from cyclonedx.model.bom import Bom


class BaseParser(ABC):

    def __init__(self, input_file: TextIOWrapper) -> None:
        self._input_file = input_file
        self._bom = Bom()

    @property
    def input_file(self) -> TextIOWrapper:
        return self._input_file

    @property
    def bom(self) -> Bom:
        return self._bom

    @bom.setter
    def bom(self, bom: Bom) -> None:
        self._bom = bom

    @abstractmethod
    def parse_bom(self) -> None:
        pass
