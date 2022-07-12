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
from typing import Any, Dict, Iterable, Optional, Set

from cyclonedx.model.component import Component
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilitySource

from .. import EcoSystem


class BaseSource(ABC):

    def __init__(self, *, config: Optional[Dict[str, Any]] = None) -> None:
        if config:
            self._configure_source(config=config)

        self._all_components: Set[Component] = set()
        self._valid_components: Set[Component] = set()

    def process_components(self, *, components: Iterable[Component]) -> None:
        self._all_components = set(components)
        self._valid_components = set(filter(lambda c: self._component_complete_for_source(component=c), components))

    @property
    def all_components(self) -> Set[Component]:
        return self._all_components

    @property
    def valid_components(self) -> Set[Component]:
        return self._valid_components

    @abstractmethod
    def get_vulnerabilities(self) -> Set[Vulnerability]:
        pass

    @abstractmethod
    def _component_complete_for_source(self, *, component: Component) -> bool:
        """
        Whether the given Component has enough data (the right fields) for us to query this data source for known
        vulnerabilities.

        :param component: Component
        :return: bool
        """
        pass

    @abstractmethod
    def _configure_source(self, *, config: Dict[str, Any]) -> None:
        """
        Perform any source specific configuration such as authentication.

        :param config: Dict[str, Any]
        :return: None
        """
        pass

    @staticmethod
    @abstractmethod
    def source() -> VulnerabilitySource:
        """
        Instance that represents this data source.

        :return: VulnerabilitySource
        """
        pass

    @staticmethod
    @abstractmethod
    def source_name() -> str:
        """
        Human-friendly name for this data source.

        :return: str
        """
        pass

    @staticmethod
    @abstractmethod
    def source_description() -> str:
        """
        Human-friendly description of this data source.

        :return: str
        """
        pass

    @staticmethod
    @abstractmethod
    def source_ecosystems() -> Set[EcoSystem]:
        """
        Which ecosystems this source has vulnerability data for.

        :return: Set[str]
        """
        pass

    @staticmethod
    @abstractmethod
    def source_url() -> str:
        """
        Public URL for this data source

        :return: str
        """
        pass
