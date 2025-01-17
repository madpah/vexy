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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/madpah/vexy/config"
	"github.com/madpah/vexy/source"
	"github.com/madpah/vexy/util"

	_ "github.com/madpah/vexy/source/ossindex"

	cdx "github.com/CycloneDX/cyclonedx-go"
	log "github.com/sirupsen/logrus"
)

const (
	DEFAULT_OUTPUT_FILENAME   = "sbom-with-vex.xml"
	DEFAULT_VEXY_LOG_FILENAME = "vexy.log"
)

var (
	debugLogging   bool   = false
	currentRuntime string = runtime.GOOS
	commit                = "unknown"
	inputSbomFile  string = "-"
	outputForce    bool   = false
	outputInJson   bool   = false
	outputVersion  string = "1.4"
	outputVexFile  string = "-"
	quiet          bool   = false
	version               = "dev"
	vexyConfigPath string = ""
	vexyLogPath    string = ""
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: vexy [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func init() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	flag.StringVar(&vexyConfigPath, "c", path.Join(cwd, config.DEFAULT_VEXY_CONFIG_FILENAME), "Configuration file for Vexy defining data sources to use and their configuration.")
	flag.BoolVar(&quiet, "q", false, "Quiet - no console output")
	flag.BoolVar(&debugLogging, "X", false, "Enable debug logging")
	flag.StringVar(&vexyLogPath, "l", path.Join(cwd, DEFAULT_VEXY_LOG_FILENAME), "Where to write Vexy's own logs to")

	// Input handling
	flag.StringVar(&inputSbomFile, "i", "-", "CycloneDX BOM to read input from. Use \"-\" to read from STDIN")

	// Output handling
	flag.StringVar(&outputVexFile, "o", path.Join(cwd, DEFAULT_OUTPUT_FILENAME), "Output file path for your SBOM with VEX (set to '-' to output to STDOUT). Setting to '-' will also disable logging output to STDOUT.")
	flag.BoolVar(&outputInJson, "json", false, "Output in JSON rather than XML")
	flag.StringVar(&outputVersion, "schema-version", "1.4", "CycloneDX schema version to output in.")
	flag.BoolVar(&outputForce, "force", false, "If outputting to a file and the stated file already exists, it will be overwritten.")
}

func printBanner() {
	println("")
	println("")
	println("                                                 __         ______  ")
	println("                                               _/  |       /      \\ ")
	println(" __     __  ______   __    __  __    __       / $$ |      /$$$$$$  |")
	println("/  \\   /  |/      \\ /  \\  /  |/  |  /  |      $$$$ |      $$$  \\$$ |")
	println("$$  \\ /$$//$$$$$$  |$$  \\/$$/ $$ |  $$ |        $$ |      $$$$  $$ |")
	println(" $$  /$$/ $$    $$ | $$  $$<  $$ |  $$ |        $$ |      $$ $$ $$ |")
	println("  $$ $$/  $$$$$$$$/  /$$$$  \\ $$ \\__$$ |       _$$ |_  __ $$ \\$$$$ |")
	println("   $$$/   $$       |/$$/ $$  |$$    $$ |      / $$   |/  |$$   $$$/ ")
	println("    $/     $$$$$$$/ $$/   $$/  $$$$$$$ |      $$$$$$/ $$/  $$$$$$/  ")
	println("                              /  \\__$$ |                            ")
	println("                              $$    $$/                             ")
	println("                               $$$$$$/                              ")
	println("")
	println(fmt.Sprintf("	Vexy Version: %s		Arch: %s", version, currentRuntime))
	println(fmt.Sprintf("               : %s", commit))
	println("")
}

func main() {
	vexyLogFile, err := getVexyLogFile()
	if err != nil {
		print(fmt.Sprintf("Unable to access Vexy log file (or create it) at %s: %v", vexyLogPath, err))
		os.Exit(1)
	}

	log.SetOutput(vexyLogFile)
	if debugLogging {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&util.LogFormatter{Module: "VEXY"})

	flag.Usage = usage
	flag.Parse()

	if !stdOutQuiet() {
		printBanner()
	}

	// Load Vexy configuration
	var config *config.VexyConfig
	config, err = config.LoadConfig(vexyConfigPath)

	if err != nil {
		panic(err)
	}

	// Configure Vulnerability Sources and see what are valid to use
	source.TheVulnerabilitySourceRegistry.SetConfiguration(config, fmt.Sprintf("%s/%s/%s", version, currentRuntime, runtime.GOARCH))

	if !stdOutQuiet() {
		println(fmt.Sprintf("Configured %d Vulnerability Sources", len(source.TheVulnerabilitySourceRegistry.ValidSources)))
	}

	// Load Input SBOM
	sbom, err := loadInputSbom()
	if err != nil {
		panic(err)
	}

	// Add Components from SBOM with each valid Vulnerability Source
	for _, c := range *sbom.Components {
		for sourceName, source := range source.TheVulnerabilitySourceRegistry.ValidSources {
			result := (*source).AddComponent(&c)
			if !result {
				log.Warn(fmt.Sprintf("Component with bom-ref '%s' is not valid for Vulnerability Source %s", c.BOMRef, sourceName))
			}
		}
	}

	// Perform VulnerabilitySource evaluations in parallel
	var sourceResponses = make(chan *source.VulnerabilitySourceEvaluationResults, len(source.TheVulnerabilitySourceRegistry.ValidSources))
	for vulnerabilitySourceName, vulnerabilitySource := range source.TheVulnerabilitySourceRegistry.ValidSources {
		log.Debug(fmt.Sprintf("Setting up evaluation using %s", vulnerabilitySourceName))
		go func(n string, s *source.VulnerabilitySource) {
			log.Info(fmt.Sprintf("Starting component evaluation with %s...", vulnerabilitySourceName))
			results, err := (*s).EvaluateComponents()
			if err != nil {
				log.Warn(fmt.Sprintf("Error whilst Evaluating Components with %s: %v", n, err))
				sourceResponses <- nil
				return
			}

			log.Info(fmt.Sprintf("Received results from %s", vulnerabilitySourceName))
			sourceResponses <- results
		}(vulnerabilitySourceName, vulnerabilitySource)
	}

	log.Debug("All evaluations concluded")

	// Collate evaluation results
	sbom.Vulnerabilities = &[]cdx.Vulnerability{}
	for i := 0; i < len(source.TheVulnerabilitySourceRegistry.ValidSources); i++ {
		sourceResults := <-sourceResponses
		log.Debug(fmt.Sprintf("Processing evaluation %d results from %s", len(sourceResults.Results), sourceResults.Source.Name))
		for _, result := range sourceResults.Results {
			if len(result.Vulnerabilities) > 0 {
				log.Debug(fmt.Sprintf("Handling %d Vulnerabilities reported by %s for %s", len(result.Vulnerabilities), sourceResults.Source.Name, result.Component.BOMRef))
				*sbom.Vulnerabilities = append(*sbom.Vulnerabilities, result.Vulnerabilities...)
			}
		}
	}

	close(sourceResponses)

	// Output Result
	outputSbomWithVex(sbom)

	log.Info("All done.")
}

func loadInputSbom() (*cdx.BOM, error) {
	bomFile, err := os.Open(inputSbomFile)
	if err != nil {
		log.Printf("Unable to read input SBOM file %s: #%v ", inputSbomFile, err)
		return nil, err
	}

	bom := new(cdx.BOM)
	var decoder cdx.BOMDecoder
	if strings.HasSuffix(inputSbomFile, ".json") {
		decoder = cdx.NewBOMDecoder(bomFile, cdx.BOMFileFormatJSON)
	} else if strings.HasSuffix(inputSbomFile, ".xml") {
		decoder = cdx.NewBOMDecoder(bomFile, cdx.BOMFileFormatXML)
	} else {
		panic("Input SBOM does not appear to be in either JSON or XML format")
	}
	if err = decoder.Decode(bom); err != nil {
		return nil, err
	}

	return bom, nil
}

func outputSbomWithVex(sbom *cdx.BOM) {
	outputFile, err := getOutputFile()
	if err != nil {
		panic(err)
	}

	bomEncoder := getBomEncoder(outputFile)

	err = bomEncoder.SetPretty(true).Encode(sbom)
	if err != nil {
		panic(err)
	}
}

func getBomEncoder(outputFile *os.File) cdx.BOMEncoder {
	if outputInJson {
		return cdx.NewBOMEncoder(outputFile, cdx.BOMFileFormatJSON)
	} else {
		return cdx.NewBOMEncoder(outputFile, cdx.BOMFileFormatXML)
	}
}

func getOutputFile() (*os.File, error) {
	if outputVexFile == "-" {
		return os.Stdout, nil
	}

	// Handle default filename extension
	if outputInJson && strings.HasSuffix(outputVexFile, DEFAULT_OUTPUT_FILENAME) {
		log.Debug("*** Default output filename - switching extension to .json as output requested in JSON")
		outputVexFile = strings.Replace(outputVexFile, ".xml", ".json", 1)
	}

	// If file does not exist, create and return
	if _, err := os.Stat(outputVexFile); errors.Is(err, os.ErrNotExist) {
		return os.Create(outputVexFile)
	} else {
		if outputForce {
			return os.Create(outputVexFile)
		}

		return nil, fmt.Errorf("File %s already exists and --force was not specified", outputVexFile)
	}
}

func getVexyLogFile() (*os.File, error) {
	// If file does not exist, create and return
	if _, err := os.Stat(vexyLogPath); errors.Is(err, os.ErrNotExist) {
		return os.Create(vexyLogPath)
	} else {
		return os.Open(vexyLogPath)
	}
}

func stdOutQuiet() bool {
	return quiet || (outputVexFile == "-")
}
