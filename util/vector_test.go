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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestParseVector(t *testing.T) {
	cases := []struct {
		inputVector         string
		expectedParseResult VectorParseResult
	}{
		{
			inputVector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			expectedParseResult: VectorParseResult{
				BaseScore: 7.3,
				Rating:    strings.ToUpper(string(cdx.SeverityHigh)),
			},
		},
		{
			inputVector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
			expectedParseResult: VectorParseResult{
				BaseScore: 7.0,
				Rating:    strings.ToUpper(string(cdx.SeverityHigh)),
			},
		},
		{
			inputVector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedParseResult: VectorParseResult{
				BaseScore: 8.1,
				Rating:    strings.ToUpper(string(cdx.SeverityHigh)),
			},
		},
		{
			inputVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			expectedParseResult: VectorParseResult{
				BaseScore: 10.0,
				Rating:    strings.ToUpper(string(cdx.SeverityCritical)),
			},
		},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("TestParseVector-%s", tc.inputVector), func(t *testing.T) {
			result, err := ParseVector(tc.inputVector)
			assert.NoError(t, err)
			assert.Equal(t, &tc.expectedParseResult, result)
		})
	}
}
