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

package config

import (
	"os"

	"gopkg.in/yaml.v3"

	log "github.com/sirupsen/logrus"
)

const DEFAULT_VEXY_CONFIG_FILENAME = ".vexy.config"

type ossIndexSource struct {
	Username *string `yaml:"username,omitempty"`
	Password *string `yaml:"password,omitempty"`
}

type osvSource struct{}

type vexySources struct {
	OssIndex *ossIndexSource `yaml:"ossindex,omitempty"`
	Osv      *osvSource      `yaml:"osv,omitempty"`
}

type VexyConfig struct {
	Sources vexySources `yaml:"sources"`
}

func (v *VexyConfig) LoadConfig(vexyConfigPath string) (*VexyConfig, error) {
	yamlFile, err := os.ReadFile(vexyConfigPath)
	if err != nil {
		log.Printf("Unable to read Vexy configuration from file %s: #%v ", vexyConfigPath, err)
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &v)
	if err != nil {
		log.Fatalf("Vexy configuration not in expected format: %v", err)
		return nil, err
	}

	return v, nil
}
