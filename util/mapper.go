/**
 * Copyright (c) 2023-present Paul Horton. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package util

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func CvssScoreToSeverity(score float64) cdx.Severity {
	if score >= 9.0 {
		return cdx.SeverityCritical
	}
	if score >= 7.0 {
		return cdx.SeverityHigh
	}
	if score >= 4.0 {
		return cdx.SeverityMedium
	}
	if score > 0.0 {
		return cdx.SeverityLow
	}
	return cdx.SeverityNone
}

func CvssVectorToScoringMethod(vector string) cdx.ScoringMethod {
	if strings.HasPrefix(vector, "CVSS:4") {
		return cdx.ScoringMethodCVSSv4
	}
	if strings.HasPrefix(vector, "CVSS:3.1/") {
		return cdx.ScoringMethodCVSSv31
	}
	if strings.HasPrefix(vector, "CVSS:3.0/") {
		return cdx.ScoringMethodCVSSv3
	}
	if strings.HasPrefix(vector, "CVSS:2.0/") {
		return cdx.ScoringMethodCVSSv2
	}
	if strings.HasPrefix(vector, "OWASP") {
		return cdx.ScoringMethodOWASP
	}
	if strings.HasPrefix(vector, "SSVC") {
		return cdx.ScoringMethodSSVC
	}
	if strings.HasPrefix(vector, "AV:") {
		return cdx.ScoringMethodCVSSv2
	}
	return cdx.ScoringMethodOther
}
