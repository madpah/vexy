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

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

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
from requests import get, post

from .. import EcoSystem
from .base import BaseSource


class OsvSource(BaseSource):
    API_BATCH_URL: str = 'https://api.osv.dev/v1/querybatch'
    API_VULNERABILITY_BY_ID: str = 'https://api.osv.dev/v1/vulns/'
    _REFERENCE_TYPES_FOR_ADVISORIES: List[str] = ['ADVISORY', 'ARTICLE', 'REPORT']
    _VERSION_RANGE_SEMVER: str = 'vers:semver/'

    def _component_complete_for_source(self, component: Component) -> bool:
        return component.purl is not None

    def _configure_source(self, config: Dict[str, Any]) -> None:
        pass

    def get_vulnerabilities(self) -> Set[Vulnerability]:
        vulnerabilities: Set[Vulnerability] = set()
        osv_data: Dict[str, Dict[str, Component]] = {}
        osv_packages: List[Dict[str, Dict[str, str]]] = []

        for component in self.valid_components:
            if component.purl:
                osv_data.update({
                    component.purl.to_string(): {
                        'component': component
                    }
                })
                osv_packages.append({
                    "package": {
                        "name": component.purl.name,
                        "purl": component.purl.to_string()
                    }
                })

        # Batch Query for Vulnerability IDs against OSV
        # @todo Handle batch limit of 1000 Components per call
        response = post(url=OsvSource.API_BATCH_URL, json={"queries": osv_packages})
        for c, v in zip(osv_packages, response.json()['results']):
            if len(v) > 0:
                for osv_vuln in v['vulns']:
                    vuln_response = get(url=f'{OsvSource.API_VULNERABILITY_BY_ID}{osv_vuln["id"]}')

                    osv_vuln_data = vuln_response.json()
                    osv_vuln_db_specific_data = osv_vuln_data[
                        'database_specific'] if 'database_specific' in osv_vuln_data else {}

                    # references
                    references: Set[VulnerabilityReference] = set()
                    if 'aliases' in osv_vuln_data:
                        for alias in osv_vuln_data['aliases']:
                            if str(alias).startswith('CVE-'):
                                references.add(VulnerabilityReference(id=alias, source=VulnerabilitySource(
                                    name='National Vulnerability Database',
                                    url=XsUri(uri=f'https://nvd.nist.gov/vuln/detail/{alias}')
                                )))

                    # ratings
                    ratings: Set[VulnerabilityRating] = set()
                    if 'severity' in osv_vuln_data:
                        for score_data in osv_vuln_data['severity']:
                            if score_data['type'] == 'CVSS_V3':
                                ratings.add(VulnerabilityRating(
                                    vector=score_data['score']
                                ))

                    # cwes
                    cwes: Optional[Iterable[int]] = None
                    if 'cwe_ids' in osv_vuln_db_specific_data:
                        cwes = list(set(map(lambda cwe: int(cwe[4:]), osv_vuln_db_specific_data['cwe_ids'])))

                    # advisories
                    advisories: Set[VulnerabilityAdvisory] = set()
                    if 'references' in osv_vuln_data:
                        for reference in osv_vuln_data['references']:
                            if reference['type'] in OsvSource._REFERENCE_TYPES_FOR_ADVISORIES:
                                advisories.add(VulnerabilityAdvisory(
                                    url=XsUri(reference['url'])
                                ))

                    # credits
                    credits_: Optional[VulnerabilityCredits] = None
                    if 'credits' in osv_vuln_data:
                        individuals: Set[OrganizationalContact] = set()
                        for credit in osv_vuln_data['credits']:
                            if 'name' in credit:
                                individuals.add(OrganizationalContact(name=credit['name']))
                        if individuals:
                            credits_ = VulnerabilityCredits(individuals=individuals)

                    # affects_targets
                    affects_targets: Set[BomTarget] = set()
                    if 'affected' in osv_vuln_data:
                        for affected in osv_vuln_data['affected']:
                            bom_target = BomTarget(ref=c['package']['purl'])
                            if 'versions' in affected:
                                for version_ in affected['versions']:
                                    bom_target.versions.add(BomTargetVersionRange(
                                        version=version_, status=ImpactAnalysisAffectedStatus.AFFECTED
                                    ))
                            if 'ranges' in affected:
                                for range_ in affected['ranges']:
                                    if range_['type'] == 'SEMVER':
                                        version_range = OsvSource._VERSION_RANGE_SEMVER
                                        for event in range_['events']:
                                            for event_type, version_ in event.items():
                                                # event_type, version_ = event.keys().pop(), event.
                                                if event_type == 'introduced':
                                                    if version_range == OsvSource._VERSION_RANGE_SEMVER:
                                                        version_range = f'{version_range}>={version_}'
                                                    else:
                                                        version_range = f'{version_range}|>={version_}'
                                                elif event_type == 'fixed':
                                                    version_range = f'{version_range}|<{version_}'

                                    bom_target.versions.add(BomTargetVersionRange(
                                        version_range=version_range,
                                        status=ImpactAnalysisAffectedStatus.AFFECTED
                                    ))
                            affects_targets.add(bom_target)

                    v = Vulnerability(
                        id=osv_vuln_data.get('id'),
                        source=OsvSource.source(),
                        references=references,
                        ratings=ratings,
                        cwes=cwes,
                        description=osv_vuln_data['summary'],
                        detail=osv_vuln_data['details'],
                        advisories=advisories,
                        published=datetime.strptime(osv_vuln_data['published'], '%Y-%m-%dT%H:%M:%SZ'),
                        updated=datetime.strptime(osv_vuln_data['modified'],
                                                  '%Y-%m-%dT%H:%M:%SZ') if 'modified' in osv_vuln_data else None,
                        credits=credits_,
                        # tools=
                        affects_targets=affects_targets
                    )

                    vulnerabilities.add(v)
        return vulnerabilities

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
