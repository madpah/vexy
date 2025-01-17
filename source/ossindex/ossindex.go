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

package ossindex

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/madpah/vexy/config"
	"github.com/madpah/vexy/source"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	log "github.com/sirupsen/logrus"
	ossindex "github.com/sonatype-nexus-community/ossindex-api-client-go"
)

const (
	COMPONENTS_PER_REQUEST = 128
)

var (
	ossIndexSource = cdx.Source{
		Name: "Sonatype OSS Index",
		URL:  "https://ossindex.sonatype.org",
	}
)

type OssIndexVulnerabilitySource struct {
	apiClient     *ossindex.APIClient
	apiContext    *context.Context
	authenticated bool
	configuration *ossindex.Configuration
	components    []*cdx.Component
	username      *string
	password      *string
}

func (s *OssIndexVulnerabilitySource) AddComponent(component *cdx.Component) bool {
	if component.PackageURL != "" {
		// Acceptable - add it
		s.components = append(s.components, component)
		return true
	}
	return false
}

func (s *OssIndexVulnerabilitySource) EvaluateComponents() (*source.VulnerabilitySourceEvaluationResults, error) {
	componentChunks := chunkComponents(s.components)

	// Create empty resultset
	var results = source.VulnerabilitySourceEvaluationResults{
		Results: make([]*source.VulnerabilitySourceEvaluationResult, 0),
		Source:  &ossIndexSource,
	}

	// Evaluate each chunk of Components
	for i := 0; i < len(componentChunks); i++ {
		requestBody := apiBodyForComonentChunk(componentChunks[i])

		var apiResponse []ossindex.ComponentReport
		var httpResponse *http.Response
		var err error
		if s.authenticated {
			apiRequest := s.apiClient.ComponentVulnerabilityReportsAPI.Post1(*s.apiContext).Body(*requestBody)
			apiResponse, httpResponse, err = apiRequest.Execute()
		} else {
			apiRequest := s.apiClient.ComponentVulnerabilityReportsAPI.Post(*s.apiContext).Body(*requestBody)
			apiResponse, httpResponse, err = apiRequest.Execute()
		}

		// For now, no retry logic
		if err != nil {
			return nil, err
		}

		log.Debug(fmt.Sprintf("OssIndex Response: %d for chunk %d", httpResponse.StatusCode, i))

		// Check HTTP Resposne Code
		if httpResponse.StatusCode == http.StatusOK {
			log.Debug(fmt.Sprintf("Processing OssIndex Response (status 200) for chunk %d", i))
			for _, cr := range apiResponse {
				if len(cr.Vulnerabilities) > 0 {
					// Processing only required if vulnerabilities are returned
					// Find CDX Component this relates to
					log.Debug(fmt.Sprintf("	Reports %d vulnerabilities for %s", len(cr.Vulnerabilities), *cr.Coordinates))
				findComponent:
					for _, c := range componentChunks[i] {
						if strings.HasPrefix(c.PackageURL, *cr.Coordinates) {
							// Got it
							log.Debug(fmt.Sprintf("		Found CDX Component for %s as %s", *cr.Coordinates, c.BOMRef))
							results.Results = append(results.Results, &source.VulnerabilitySourceEvaluationResult{
								Component:       c,
								Vulnerabilities: ossIndexVulnerabiltiesToCdxVulnerabilties(&cr.Vulnerabilities, c.BOMRef),
							})
							break findComponent
						}
					}
				}
			}
		}
	}

	return &results, nil
}

func apiBodyForComonentChunk(components []*cdx.Component) *ossindex.ComponentReportRequest {
	var Coordinates = make([]string, 0)

	for _, c := range components {
		purl, _ := packageurl.FromString(c.PackageURL)
		// For Maven, qualifiers need removing
		if purl.Type == packageurl.TypeMaven {
			purl.Qualifiers = packageurl.Qualifiers{}
		}

		Coordinates = append(Coordinates, purl.ToString())
	}

	requestBody := ossindex.ComponentReportRequest{
		Coordinates: Coordinates,
	}

	return &requestBody
}

func chunkComponents(components []*cdx.Component) [][]*cdx.Component {
	var componentChunks [][]*cdx.Component

	for i := 0; i < len(components); i += COMPONENTS_PER_REQUEST {
		end := i + COMPONENTS_PER_REQUEST

		if end > len(components) {
			end = len(components)
		}

		componentChunks = append(componentChunks, components[i:end])
	}

	log.Debug(fmt.Sprintf("OssIndexVulnerabilitySource: Split %d components into %d chunks", len(components), len(componentChunks)))

	return componentChunks
}

func ossIndexVulnerabiltiesToCdxVulnerabilties(input *[]ossindex.ComponentReportVulnerability, componentPurl string) []cdx.Vulnerability {
	var output []cdx.Vulnerability
	componentPackageUrl, _ := packageurl.FromString(componentPurl)

	for _, i := range *input {
		var cvssScore = float64(*i.CvssScore)
		cweId, _ := strconv.Atoi((*i.Cwe)[4:])

		cdxV := cdx.Vulnerability{
			BOMRef: uuid.NewString(),
			ID:     *i.Cve,
			Source: &ossIndexSource,
			References: &[]cdx.VulnerabilityReference{{
				ID:     *i.Id,
				Source: &ossIndexSource,
			}},
			Ratings: &[]cdx.VulnerabilityRating{{
				Source:   &ossIndexSource,
				Score:    &cvssScore,
				Severity: cvssScoreToSeverity(cvssScore),
				Method:   cvssVectorToScoringMethod(*i.CvssVector),
				Vector:   *i.CvssVector,
			}},
			CWEs:        &[]int{cweId},
			Description: *i.Title,
			Detail:      *i.Description,
			Advisories:  &[]cdx.Advisory{},
			Affects: &[]cdx.Affects{{
				Ref: componentPurl,
				Range: &[]cdx.AffectedVersions{{
					Version: componentPackageUrl.Version,
					Status:  cdx.VulnerabilityStatusAffected,
				}},
			}},
		}

		var cdxAdvisories []cdx.Advisory
		for _, a := range i.ExternalReferences {
			cdxAdvisories = append(cdxAdvisories, cdx.Advisory{
				URL: a,
			})
		}
		cdxV.Advisories = &cdxAdvisories

		output = append(output, cdxV)
	}

	return output
}

func cvssScoreToSeverity(score float64) cdx.Severity {
	if score >= 9.0 {
		return cdx.SeverityCritical
	}
	if score >= 7.0 {
		return cdx.SeverityHigh
	}
	if score >= 4.0 {
		return cdx.SeverityMedium
	}
	if score >= 0.0 {
		return cdx.SeverityLow
	}
	return cdx.SeverityNone
}

func cvssVectorToScoringMethod(vector string) cdx.ScoringMethod {
	if strings.HasPrefix(vector, "CVSS:4") {
		return cdx.ScoringMethodCVSSv4
	}
	if strings.HasPrefix(vector, "CVSS:3.1/") {
		return cdx.ScoringMethodCVSSv31
	}
	if strings.HasPrefix(vector, "CVSS:3.0/") {
		return cdx.ScoringMethodCVSSv3
	}
	if strings.HasPrefix(vector, "CVSS:2") {
		return cdx.ScoringMethodCVSSv2
	}
	if strings.HasPrefix(vector, "OWASP") {
		return cdx.ScoringMethodOWASP
	}
	return cdx.ScoringMethodOther
}

func (s *OssIndexVulnerabilitySource) SetConfiguration(config *config.VexyConfig, vexyVersion string) bool {
	if config.Sources.OssIndex != nil {
		if config.Sources.OssIndex.Username != nil {
			s.username = config.Sources.OssIndex.Username
		}
		if config.Sources.OssIndex.Password != nil {
			s.password = config.Sources.OssIndex.Password
		}
	}

	// Validate we have both username & password or neither
	if (s.username == nil && s.password != nil) || (s.username != nil && s.password == nil) {
		log.Warn("OssIndex Source is incorrectly configured and will be ignored - Username and Password must both be set or unset.")
		return false
	}

	// Setup API Client & Context
	ossindexConfiguration := ossindex.NewConfiguration()
	ossindexConfiguration.UserAgent = fmt.Sprintf("vexy/%s", vexyVersion)
	s.apiClient = ossindex.NewAPIClient(ossindexConfiguration)

	var c context.Context
	if s.username != nil && s.password != nil {
		c = context.WithValue(context.Background(), ossindex.ContextBasicAuth, ossindex.BasicAuth{
			UserName: *s.username,
			Password: *s.password,
		})
		s.authenticated = true
	} else {
		c = context.Background()
	}
	s.apiContext = &c

	return true
}

func init() {
	source.TheVulnerabilitySourceRegistry.RegisterVulnerabilitySource("ossindex", &OssIndexVulnerabilitySource{
		components: make([]*cdx.Component, 0),
	})
}
