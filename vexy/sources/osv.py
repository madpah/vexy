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

from typing import Any, Dict, List, Set

from cyclonedx.model import OrganizationalContact, XsUri
from cyclonedx.model.component import Component
from cyclonedx.model.impact_analysis import ImpactAnalysisAffectedStatus
from cyclonedx.model.vulnerability import (
    BomTarget,
    BomTargetVersionRange,
    Vulnerability,
    VulnerabilityAdvisory,
    VulnerabilityCredits,
    VulnerabilityRating,
    VulnerabilityReference,
    VulnerabilitySource,
)
from osv.api import OsvApi
from osv.model import OsvPackage, OsvReferenceType, OsvSeverityType

from .. import EcoSystem
from .base import BaseSource


class OsvSource(BaseSource):

    def get_vulnerabilities(self) -> Set[Vulnerability]:
        osv = OsvApi()

        vulnerabilities: Set[Vulnerability] = set()

        for component in self.valid_components:
            osv_vulnerabilities = osv.query(package=OsvPackage(purl=component.purl))
            for osv_v in osv_vulnerabilities:
                affected_versions: List[BomTargetVersionRange] = []
                for affected in osv_v.affected:
                    if affected.ranges:
                        for r in affected.ranges:
                            affected_versions.append(BomTargetVersionRange(
                                version_range=r.as_purl_vers(), status=ImpactAnalysisAffectedStatus.AFFECTED
                            ))
                    for v in affected.versions:
                        affected_versions.append(BomTargetVersionRange(
                            version=v, status=ImpactAnalysisAffectedStatus.AFFECTED
                        ))

                ratings: List[VulnerabilityRating] = []
                for severity in osv_v.severity:
                    if severity.type_ == OsvSeverityType.CVSS_V3:
                        ratings.append(VulnerabilityRating(
                            vector=severity.score
                        ))

                advisories: List[VulnerabilityAdvisory] = []
                for ref in osv_v.references:
                    if ref.type_ == OsvReferenceType.ADVISORY:
                        advisories.append(VulnerabilityAdvisory(url=XsUri(ref.url)))

                credits_ = None
                if osv_v.credits:
                    credit = osv_v.credits.pop()
                    contact_1 = credit.contact.pop()
                    credits_ = VulnerabilityCredits(individuals=[
                        OrganizationalContact(
                            name=credit.name,
                            phone=contact_1 if '@' not in contact_1 else None,
                            email=contact_1 if '@' in contact_1 else None
                        )
                    ])

                vulnerabilities.add(
                    Vulnerability(
                        source=OsvSource.source(),
                        references=[
                            VulnerabilityReference(id=osv_v.id_, source=OsvSource.source())
                        ],
                        ratings=ratings,
                        cwes=None,
                        description=osv_v.summary,
                        detail=osv_v.details,
                        advisories=advisories,
                        created=osv_v.published,
                        published=osv_v.published,
                        updated=osv_v.modified if osv_v.modified else None,
                        credits=credits_,
                        affects_targets=[
                            BomTarget(
                                ref=component.bom_ref.value,
                                versions=affected_versions
                            )
                        ],
                    )
                )

        return vulnerabilities

    def _component_complete_for_source(self, *, component: Component) -> bool:
        return component.purl is not None

    def _configure_source(self, *, config: Dict[str, Any]) -> None:
        pass

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
        return 'An open, precise, and distributed approach to producing and consuming vulnerability information for ' \
               'open source.'

    @staticmethod
    def source_ecosystems() -> Set[EcoSystem]:
        return {
            EcoSystem.CARGO, EcoSystem.COMPOSER, EcoSystem.DEBIAN, EcoSystem.GO, EcoSystem.MAVEN, EcoSystem.NPM,
            EcoSystem.NUGET, EcoSystem.PYPI, EcoSystem.RPM, EcoSystem.RUBY_GEM
        }

    @staticmethod
    def source_url() -> str:
        """
        Public URL for this data source

        :return: str
        """
        return 'https://osv.dev/'
