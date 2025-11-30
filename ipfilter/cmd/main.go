package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	ipfilter "ipfilter/ipfilter/filter"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	version = "1.0.0"
)

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

	println("IP Filter Tool - Version:", version)

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
		rawData, errors = fetchURL(githubMetaURL)
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

		var final []byte

		// ---------------------------------------------------------
		// OUTPUT TO FILE
		// ---------------------------------------------------------
		ifLog("Writing policy to %s", *output)

		if *minify {
			final = policyJSON
		} else {
			var prettyJSON interface{}
			err := json.Unmarshal(policyJSON, &prettyJSON)
			if err != nil {
				log.Fatalf("Error during JSON pretty print: %v", err)
			}
			final, err = json.MarshalIndent(prettyJSON, "", "  ")
			if err != nil {
				log.Fatalf("Error during JSON pretty print: %v", err)
			}
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

func fetchURL(githubMetaURL string) ([]byte, error) {
	resp, err := http.Get(githubMetaURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
