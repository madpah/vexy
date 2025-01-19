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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestCvssScoreToSeverity(t *testing.T) {
	cases := []struct {
		inputScore       float64
		expectedSeverity cdx.Severity
	}{
		{
			inputScore:       10.0,
			expectedSeverity: cdx.SeverityCritical,
		},
		{
			inputScore:       9.0,
			expectedSeverity: cdx.SeverityCritical,
		},
		{
			inputScore:       8.0,
			expectedSeverity: cdx.SeverityHigh,
		},
		{
			inputScore:       7.0,
			expectedSeverity: cdx.SeverityHigh,
		},
		{
			inputScore:       5.0,
			expectedSeverity: cdx.SeverityMedium,
		},
		{
			inputScore:       4.0,
			expectedSeverity: cdx.SeverityMedium,
		},
		{
			inputScore:       2.0,
			expectedSeverity: cdx.SeverityLow,
		},
		{
			inputScore:       0.0,
			expectedSeverity: cdx.SeverityNone,
		},
		{
			inputScore:       -1.0,
			expectedSeverity: cdx.SeverityNone,
		},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("CvssScoreToSeverity-%0.2f", tc.inputScore), func(t *testing.T) {
			assert.Equal(t, tc.expectedSeverity, CvssScoreToSeverity(tc.inputScore))
		})
	}
}

func TestCvssVectorToScoringMethod(t *testing.T) {
	cases := []struct {
		inputVector           string
		expectedScoringMethod cdx.ScoringMethod
	}{
		{
			inputVector:           "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			expectedScoringMethod: cdx.ScoringMethodCVSSv4,
		},
		{
			inputVector:           "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
			expectedScoringMethod: cdx.ScoringMethodCVSSv31,
		},
		{
			inputVector:           "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedScoringMethod: cdx.ScoringMethodCVSSv3,
		},
		{
			inputVector:           "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
			expectedScoringMethod: cdx.ScoringMethodCVSSv2,
		},
		{
			inputVector:           "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			expectedScoringMethod: cdx.ScoringMethodCVSSv2,
		},
		{
			inputVector:           "SSVCv2/E:P/A:Y/T:T/P:E/B:I/M:H/P:E/B:I/M:H/D:A/2025-01-19T15:10:26Z/",
			expectedScoringMethod: cdx.ScoringMethodSSVC,
		},
		{
			inputVector:           "SOMETHING",
			expectedScoringMethod: cdx.ScoringMethodOther,
		},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("CvssVectorToScoringMethod-%s", tc.inputVector), func(t *testing.T) {
			assert.Equal(t, tc.expectedScoringMethod, CvssVectorToScoringMethod(tc.inputVector))
		})
	}
}
