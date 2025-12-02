package ipfilter

import (
	"encoding/json"
)

func GeneratePolicy(minify bool) ([]byte, error) {
	// 1. Fetch GitHub meta
	rawData, err := FetchURL("https://api.github.com/meta")
	if err != nil {
		return nil, err
	}

	// 2. Extract and filter
	ipfiltered, err := ExtractActionsAndFilterIP4(rawData)
	if err != nil {
		return nil, err
	}

	// 3. Build deny policy
	policyJSON, err := BuildDenyPolicy(ipfiltered)
	if err != nil {
		return nil, err
	}

	// 4. Unmarshal → reorder
	var doc Policy
	if err := json.Unmarshal(policyJSON, &doc); err != nil {
		return nil, err
	}

	kvs := []KV{
		{Key: "Version", Value: doc.Version},
		{Key: "Id", Value: doc.Id},
		{Key: "Statement", Value: doc.Statement},
	}

	reordered, err := ReorderJson(kvs, minify)
	if err != nil {
		return nil, err
	}

	return reordered, nil
}
