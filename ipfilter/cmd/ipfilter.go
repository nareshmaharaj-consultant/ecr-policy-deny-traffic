package main

import (
	"encoding/json"
	"flag"
	"fmt"
	ipfilter "ipfilter/ipfilter/filter"
	"log"
	"os"
	"time"
)

var (
	version = "1.0.0"
)

// Main function
// ---------------------------------------------------------
// ENTRY POINT FOR COMMAND LINE TOOL
// NOTE: This is separate from the Lambda handler in lambda.go
// SO we have two main() functions in the project.
// This main() is only used when building the CLI tool.
// Remove the 'X' from 'mainX' to enable it.
// ---------------------------------------------------------
func main() {

	startTime := time.Now()

	// GitHub provides a metadata endpoint that lists all public IP ranges.
	// We only care about the Actions IP ranges.
	const githubMetaURL = "https://api.github.com/meta"

	// Command-line flags
	source := flag.String("source", "github", "Source provider: only 'github' is supported for now")
	quiet := flag.Bool("quiet", false, "Keeps log output to zilch, only errors will be shown")
	output := flag.String("output", "policy.json", "Output file for the generated policy")
	minify := flag.Bool("minify", false, "Minify the output JSON policy")
	flag.Parse()

	// Log Function
	ifLog := func(msg string, args ...interface{}) {
		if !*quiet {
			log.Printf(msg, args...)
		}
	}

	ifLog("IP Filter Tool - Version: %s", version)

	var rawData []byte
	var errors error

	switch *source {
	case "github":
		// Fetch and process GitHub IP ranges
		if !*quiet {
			ifLog("Fetching IP ranges from GitHub...")
		}
		// ---------------------------------------------------------
		// FETCH SOURCE METADATA
		// ---------------------------------------------------------
		// For GitHub, we fetch https://api.github.com/meta which contains a large
		// JSON document listing all GitHub public IP ranges, broken down by service.
		// The TDD tests have already validated that our extractors handle this shape.
		// ---------------------------------------------------------
		rawData, errors = ipfilter.FetchURL(githubMetaURL)
		if errors != nil {
			log.Fatalf("Error fetching GitHub metadata: %v", errors)
		}

		// ---------------------------------------------------------
		// EXTRACT IP RANGES
		// ---------------------------------------------------------
		ipfiltered, errors := ipfilter.ExtractActionsAndFilterIP4(rawData)
		if errors != nil {
			log.Fatalf("Error extracting GitHub Actions IP ranges: %v", errors)
		}

		// ---------------------------------------------------------
		// CREATE AWS DENY POLICY FROM RESULTS - UNMARCHASLLED JSON
		// ---------------------------------------------------------
		policyJSON, errors := ipfilter.BuildDenyPolicy(ipfiltered)
		if errors != nil {
			log.Fatalf("Error building deny policy: %v", errors)
		}

		// ---------------------------------------------------------
		// HERE WE RE-ORDER THE POLICY BASED ON KEY VALUES PROVIDED
		// ---------------------------------------------------------
		var doc ipfilter.Policy
		err := json.Unmarshal(policyJSON, &doc)
		if err != nil {
			log.Fatalf("Failed to unmarshal policy JSON: %v", err)
		}

		// Policy Document UnMarshalled ReOrdered based on Key Value provided
		kvs := []ipfilter.KV{
			{Key: "Version", Value: doc.Version},
			{Key: "Id", Value: doc.Id},
			{Key: "Statement", Value: doc.Statement},
		}

		reorderdJson, err := ipfilter.ReorderJson(kvs, false)
		if err != nil {
			log.Fatalf("Unexpected error: %v", err)
		}

		var final []byte

		// ---------------------------------------------------------
		// OUTPUT TO FILE
		// ---------------------------------------------------------
		ifLog("Writing policy to %s", *output)

		if *minify {
			final = policyJSON
		} else {
			//	var prettyJSON any
			//	err := json.Unmarshal(reorderdJson, &prettyJSON)
			//	if err != nil {
			//		log.Fatalf("Error during JSON pretty print: %v", err)
			//	}
			final = reorderdJson
		}

		// ---------------------------------------------------------
		// WRITE OUTPUT
		// ---------------------------------------------------------
		// If --output is not provided, print to stdout.
		// Otherwise write to the specified file.
		// ---------------------------------------------------------
		if *output == "" {
			fmt.Println(string(final))
		} else {
			if err := os.WriteFile(*output, final, 0644); err != nil {
				log.Fatalf("failed writing file: %v", err)
			}
			ifLog("Policy written to %s", *output)
		}
		ifLog("Time taken: %s", time.Since(startTime))

	default:
		println("Unsupported source provider:", *source)
	}

}
