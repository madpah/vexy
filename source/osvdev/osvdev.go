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

package osvdev

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/madpah/vexy/config"
	"github.com/madpah/vexy/source"
	"github.com/madpah/vexy/util"

	cdx "github.com/CycloneDX/cyclonedx-go"
	osvdev "github.com/madpah/osv-dev-api-client-go"
	log "github.com/sirupsen/logrus"
)

var (
	osvDevSource = cdx.Source{
		Name: "OSV Vulnerability Database",
		URL:  "https://osv.dev",
	}
)

type OsvDevVulnerabilitySource struct {
	apiClient  *osvdev.APIClient
	apiContext *context.Context
	components []*cdx.Component
}

func (s *OsvDevVulnerabilitySource) AddComponent(component *cdx.Component) bool {
	if component.PackageURL != "" {
		// Acceptable - add it
		s.components = append(s.components, component)
		return true
	}
	return false
}

func (s *OsvDevVulnerabilitySource) EvaluateComponents() (*source.VulnerabilitySourceEvaluationResults, error) {
	// Create empty resultset
	var results = source.VulnerabilitySourceEvaluationResults{
		Results: make([]*source.VulnerabilitySourceEvaluationResult, 0),
		Source:  &osvDevSource,
	}

	log.Debug("Beginning OSV.dev EvaluateComponents")
	for i, component := range s.components {
		log.Debug(fmt.Sprintf("Processing Component %5d: %s", i, component.BOMRef))
		apiQueryRequest := s.apiClient.OSVAPI.OSVQueryAffected(*s.apiContext).Body(osvdev.V1Query{
			Package: &osvdev.OsvPackage{
				Purl: &component.PackageURL,
			},
		})
		apiQueryResponse, httpResponse, err := apiQueryRequest.Execute()

		// For now, no retry logic
		if err != nil {
			return nil, err
		}

		// Check HTTP Resposne Code
		if httpResponse.StatusCode == http.StatusOK {
			if apiQueryResponse.NextPageToken != nil {
				log.Debug(fmt.Sprintf("	-> *** Got Query Response for %s - Next Page Token: %s", component.PackageURL, apiQueryResponse.GetNextPageToken()))
			}

			if len(apiQueryResponse.Vulns) > 0 {
				// Vulnerabilities returned
			findComponent:
				for _, c := range s.components {
					if strings.HasPrefix(c.PackageURL, component.PackageURL) {
						// Got it
						log.Debug(fmt.Sprintf("		Found CDX Component for %s as %s", component.PackageURL, c.BOMRef))
						results.Results = append(results.Results, &source.VulnerabilitySourceEvaluationResult{
							Component:       c,
							Vulnerabilities: osvDevVulnerabilitiesToCdxVulnerabilities(&apiQueryResponse.Vulns, c.BOMRef),
						})
						break findComponent
					}
				}
			}
		}
	}

	return &results, nil
}

func osvDevVulnerabilitiesToCdxVulnerabilities(input *[]osvdev.OsvVulnerability, componentPurl string) []cdx.Vulnerability {
	var output []cdx.Vulnerability
	// componentPackageUrl, _ := packageurl.FromString(componentPurl)

	for _, i := range *input {
		// var ParsedVector = util.ParseVector(i.Severity)
		// var cvssScore = float64(*i.CvssScore)
		// cweId, _ := strconv.Atoi((*i.Cwe)[4:])

		cdxV := cdx.Vulnerability{
			BOMRef: uuid.NewString(),
			ID:     *i.Id,
			Source: &osvDevSource,
			// CWEs:        &[]int{cweId},
			Description: *i.Summary,
			Detail:      *i.Details,
			Published:   i.Published.String(),
			Updated:     i.Modified.String(),
			// Affects: &[]cdx.Affects{{
			// 	Ref: componentPurl,
			// 	Range: &[]cdx.AffectedVersions{{
			// 		Version: componentPackageUrl.Version,
			// 		Status:  cdx.VulnerabilityStatusAffected,
			// 	}},
			// }},
		}

		var ratings []cdx.VulnerabilityRating
		for _, severity := range i.Severity {
			parsedVector, err := util.ParseVector(*severity.Score)
			if err != nil {
				log.Debug(fmt.Sprintf("Failed to parse Vector '%s' - skipping when mapping to CycloneDX: %v", *severity.Score, err))
			}
			ratings = append(ratings, cdx.VulnerabilityRating{
				Source:   &osvDevSource,
				Score:    &parsedVector.BaseScore,
				Severity: util.CvssScoreToSeverity(parsedVector.BaseScore),
				Method:   util.CvssVectorToScoringMethod(*severity.Score),
				Vector:   *severity.Score,
			})
		}
		cdxV.Ratings = &ratings

		// TODO: i.DatabaseSpecific has no schema and thus does not get deserialized by the generated library
		//
		// for k, v := range i.DatabaseSpecific {
		// 	log.Debug(fmt.Sprintf("  DB Specific - %s -> %v", k, v))
		// }

		// cwesData, ok := i.DatabaseSpecific["cwe_ids"]
		// if ok {
		// 	log.Debug(fmt.Sprintf("CWE_IDS exists for %s", *i.Id))
		// 	cwes, ok := cwesData.([]string)
		// 	if ok {
		// 		log.Debug(fmt.Sprintf("		--> CWE_IDS exists for %s", *i.Id))
		// 		for _, cweStr := range cwes {
		// 			cweId, _ := strconv.Atoi((cweStr)[4:])
		// 			*cdxV.CWEs = append(*cdxV.CWEs, cweId)
		// 		}
		// 	}
		// } else {
		// 	log.Debug(fmt.Sprintf("CWE_IDS DOES NOT exists for %s, %v", *i.Id, i.DatabaseSpecific))
		// }

		for _, alias := range i.Aliases {
			var references []cdx.VulnerabilityReference
			if strings.HasPrefix(alias, "CVE-") {
				references = append(references, cdx.VulnerabilityReference{
					ID:     alias,
					Source: &source.NvdSource,
				})
			}
			cdxV.References = &references
		}

		var cdxAdvisories []cdx.Advisory
		for _, ref := range i.References {
			if *ref.Type == osvdev.OSVREFERENCETYPE_ADVISORY {
				cdxAdvisories = append(cdxAdvisories, cdx.Advisory{
					URL: *ref.Url,
				})
			}
		}
		cdxV.Advisories = &cdxAdvisories

		var cdxAffectsSlice = &[]cdx.Affects{}
		for _, affected := range i.Affected {
			if strings.HasPrefix(componentPurl, *affected.Package.Purl) {
				var cdxAffects = cdx.Affects{
					Ref:   componentPurl,
					Range: &[]cdx.AffectedVersions{},
				}

				// Add any specific versions stated as Affected
				for _, affectedVersion := range affected.Versions {
					*cdxAffects.Range = append(*cdxAffects.Range, cdx.AffectedVersions{
						Version: affectedVersion,
						Status:  cdx.VulnerabilityStatusAffected,
					})
				}

				// if len(affected.Ranges) > 0 {
				// 	affectedVersionRanges := []cdx.AffectedVersions{}
				// 	for _, affectedRange := range affected.Ranges {
				// 		affectedVersionRanges = append(affectedVersionRanges, cdx.AffectedVersions{

				// 		})
				// 	}
				// }
				// cdxAffects = append(cdxAffects, cdx.Affects{
				// 	Ref: componentPurl,
				// 	Range: &[]cdx.AffectedVersions{},
				// })

				if len(*cdxAffects.Range) > 0 {
					*cdxAffectsSlice = append(*cdxAffectsSlice, cdxAffects)
				}
			} else {
				log.Debug(fmt.Sprintf("Affected does not match purl. Expected %s got %s", componentPurl, *affected.Package.Purl))
			}
		}
		cdxV.Affects = cdxAffectsSlice

		output = append(output, cdxV)
	}

	return output
}

func (s *OsvDevVulnerabilitySource) SetConfiguration(config *config.VexyConfig, vexyVersion string) bool {
	// Setup API Client & Context
	osvdevConfiguration := osvdev.NewConfiguration()
	osvdevConfiguration.Servers = osvdev.ServerConfigurations{
		{
			URL: "https://api.osv.dev",
		},
	}
	osvdevConfiguration.UserAgent = fmt.Sprintf("vexy/%s", vexyVersion)
	s.apiClient = osvdev.NewAPIClient(osvdevConfiguration)

	var c context.Context = context.Background()
	s.apiContext = &c

	return true
}

func init() {
	source.TheVulnerabilitySourceRegistry.RegisterVulnerabilitySource("osv.dev", &OsvDevVulnerabilitySource{
		components: make([]*cdx.Component, 0),
	})
}
