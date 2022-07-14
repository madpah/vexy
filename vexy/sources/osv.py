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

from requests import post
from typing import Any, Dict, Set

from cyclonedx.model import XsUri
from cyclonedx.model.component import Component
from cyclonedx.model.impact_analysis import ImpactAnalysisAffectedStatus
from cyclonedx.model.vulnerability import (
    BomTarget,
    BomTargetVersionRange,
    Vulnerability,
    VulnerabilityAdvisory,
    VulnerabilityRating,
    VulnerabilityReference,
    VulnerabilityScoreSource,
    VulnerabilitySeverity,
    VulnerabilitySource,
)

from .. import EcoSystem
from .base import BaseSource


class OsvSource(BaseSource):

    API_BATCH_URL: str = 'https://api.osv.dev/v1/querybatch'

    def _component_complete_for_source(self, component: Component) -> bool:
        return component.purl is not None

    def _configure_source(self, config: Dict[str, Any]) -> None:
        pass

    def get_vulnerabilities(self) -> Set[Vulnerability]:
        osv_packages: list[dict[str, dict[str, str]]] = []

        for component in self.valid_components:
            osv_packages.append({
                "package": {
                    "name": component.purl.name,
                    "purl": component.purl.to_string()
                }
            })

        print(osv_packages)

        response = post(url=OsvSource.API_BATCH_URL, json={"queries": osv_packages})
        print(response.json())

        # vulnerabilities: Set[Vulnerability] = set()
        #
        # for ossi_c in ossi_results:
        #     if ossi_c.vulnerabilities:
        #         for ossi_v in ossi_c.vulnerabilities:
        #             v_source = VulnerabilitySource(
        #                 name=OssIndexSource.source_name(), url=XsUri(uri=ossi_v.reference)
        #             )
        #             v = Vulnerability(
        #                 source=OssIndexSource.source(),
        #                 references=[
        #                     VulnerabilityReference(id=ossi_v.id, source=v_source)
        #                 ],
        #                 cwes=[int(ossi_v.cwe[4:])] if ossi_v.cwe else None,
        #                 description=ossi_v.title,
        #                 detail=ossi_v.description,
        #                 affects_targets=[
        #                     BomTarget(
        #                         ref=ossi_c.get_package_url().to_string(),
        #                         versions=[
        #                             BomTargetVersionRange(
        #                                 version=ossi_c.get_package_url().version,
        #                                 status=ImpactAnalysisAffectedStatus.UNKNOWN
        #                             )
        #                         ]
        #                     )
        #                 ]
        #             )
        #
        #             if ossi_v.cvss_score:
        #                 v.ratings.add(
        #                     VulnerabilityRating(
        #                         source=v_source, score=Decimal(
        #                             ossi_v.cvss_score
        #                         ) if ossi_v.cvss_score else None,
        #                         severity=VulnerabilitySeverity.get_from_cvss_scores(
        #                             (ossi_v.cvss_score,)
        #                         ) if ossi_v.cvss_score else None,
        #                         method=VulnerabilityScoreSource.get_from_vector(
        #                             vector=ossi_v.cvss_vector
        #                         ) if ossi_v.cvss_vector else None,
        #                         vector=ossi_v.cvss_vector)
        #                 )
        #
        #             for ext_ref in ossi_v.external_references:
        #                 v.advisories.add(VulnerabilityAdvisory(url=XsUri(uri=ext_ref)))
        #
        #             vulnerabilities.add(v)
        #
        # return vulnerabilities

    @staticmethod
    def source() -> VulnerabilitySource:
        """
        Instance that represents this data source.

        :return: VulnerabilitySource
        """
        return VulnerabilitySource(name=OsvSource.source_name(), url=XsUri(uri=OsvSource.source_url()))

    @staticmethod
    def source_name() -> str:
        return 'OSV'

    @staticmethod
    def source_description() -> str:
        return 'Coming soon!'

    @staticmethod
    def source_ecosystems() -> Set[EcoSystem]:
        return {
            EcoSystem.CARGO, EcoSystem.COCOAPODS, EcoSystem.COMPOSER, EcoSystem.COMPOSER, EcoSystem.CONAN,
            EcoSystem.CONDA, EcoSystem.CRAN, EcoSystem.GO, EcoSystem.MAVEN, EcoSystem.NPM, EcoSystem.NUGET,
            EcoSystem.PYPI, EcoSystem.RPM, EcoSystem.RUBY_GEM, EcoSystem.SWIFT
        }

    @staticmethod
    def source_url() -> str:
        """
        Public URL for this data source

        :return: str
        """
        return 'https://osv.dev/'
