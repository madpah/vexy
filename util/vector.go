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

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

type VectorParseResult struct {
	BaseScore float64
	Rating    string
}

func ParseVector(vector string) (*VectorParseResult, error) {
	result := VectorParseResult{}

	switch {
	default: // Should be CVSS v2.0 or is invalid
		cvss, err := gocvss20.ParseVector(vector)
		if err != nil {
			return nil, err
		}
		result.BaseScore = cvss.BaseScore()
		result.BaseScore = cvss.BaseScore()
		rat, err := gocvss40.Rating(cvss.BaseScore())
		if err != nil {
			return nil, err
		}
		result.Rating = rat

	case strings.HasPrefix(vector, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(vector)
		if err != nil {
			return nil, err
		}
		result.BaseScore = cvss.BaseScore()
		result.BaseScore = cvss.BaseScore()
		rat, err := gocvss40.Rating(cvss.BaseScore())
		if err != nil {
			return nil, err
		}
		result.Rating = rat

	case strings.HasPrefix(vector, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(vector)
		if err != nil {
			return nil, err
		}
		result.BaseScore = cvss.BaseScore()
		rat, err := gocvss40.Rating(cvss.BaseScore())
		if err != nil {
			return nil, err
		}
		result.Rating = rat

	case strings.HasPrefix(vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			return nil, err
		}
		result.BaseScore = cvss.Score()
		rat, err := gocvss40.Rating(cvss.Score())
		if err != nil {
			return nil, err
		}
		result.Rating = rat
	}

	return &result, nil
}
