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

"""
Contains classes and methods for parsing a Component List from CycloneDX BOM documents.
"""

import json
import keyword
from typing import Any, Dict, Set, cast
from xml.dom.minidom import Element, Text, parseString

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component

# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore

from . import BaseParser

_KEYWORDS: Set[str] = set(keyword.kwlist)
_JSON_IGNORE_KEYS = ['externalReferences', 'hashes', 'licenses']
_JSON_KEY_MAPPINGS = {
    'type': 'component_type'
}
_XML_IGNORE_KEYS = ['externalReferences', 'hashes', 'licenses']


class CycloneDxJsonParser(BaseParser):

    def parse_bom(self) -> None:
        with self.input_file as input_file:
            bom_data = json.loads(input_file.read())

            # Handle Serial Number and Version
            self.bom = Bom(serial_number=bom_data.get('serialNumber'), version=bom_data.get('version'))

            # Process Metadata
            bom_metadata_data = bom_data.get('metadata')
            self.bom.metadata.component = _component_from_json(bom_metadata_data.get('component'))

            # Process Components
            bom_component_data = bom_data.get('components')
            for c in bom_component_data:
                self.bom.components.add(_component_from_json(json_data=c))


class CycloneDxXmlParser(BaseParser):

    def parse_bom(self) -> None:
        with self.input_file as input_file:
            bom_data = parseString(input_file.read())

            assert bom_data.documentElement.tagName == 'bom'

            # Handle Serial Number and Version
            bom_attributes = bom_data.documentElement.attributes
            self.bom = Bom(
                serial_number=bom_attributes.get('serialNumber').value, version=bom_attributes.get('version').value
            )

            # Process Metadata
            bom_metadata_data = bom_data.documentElement.getElementsByTagName('metadata')[0]
            self.bom.metadata.component = _component_from_xml(
                xml_element=bom_metadata_data.getElementsByTagName('component')[0]
            )

            # Process Components
            bom_component_data = bom_data.documentElement.getElementsByTagName('components')[0]
            bom_components_data = bom_component_data.getElementsByTagName('component')
            for c in bom_components_data:
                self.bom.components.add(_component_from_xml(xml_element=c))


def _component_from_json(json_data: Dict[str, Any]) -> Component:
    jd = {}
    for k, v in json_data.items():
        if k in _JSON_IGNORE_KEYS:
            continue
        k = k.replace('-', '_')
        if k in _KEYWORDS:
            k = f'{k}_'
        if k in _JSON_KEY_MAPPINGS:
            k = _JSON_KEY_MAPPINGS[k]
        if k == 'purl':
            v = PackageURL.from_string(purl=v)
        jd.update({k: v})

    return Component(**jd)


def _component_from_xml(xml_element: Element) -> Component:
    jd = {}
    for e in xml_element.childNodes:
        if isinstance(e, Element):
            if e.nodeName == 'purl':
                jd.update({e.nodeName: PackageURL.from_string(purl=str(cast(Text, e.firstChild).data).strip())})
            elif e.nodeName not in _XML_IGNORE_KEYS:
                jd.update({e.nodeName: str(cast(Text, e.firstChild).data).strip()})

    return Component(**jd)
