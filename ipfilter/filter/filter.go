package ipfilter

import (
	"encoding/json"
	"net"
)

// filterIP4Addresses filters and returns only IPv4 addresses from the given list.
func filterIP4Addresses(ips []string) []string {
	var filtered []string
	for _, ip := range ips {
		parsedIP, _, err := net.ParseCIDR(ip)
		if err != nil {
			continue // Skip invalid IPs
		}
		if parsedIP.To4() != nil {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

// ExtractActions extracts CIDR blocks related to GitHub Actions from the provided JSON data.
type ActionsData struct {
	Actions []string `json:"actions"`
}

func ExtractActions(jsonData []byte) ([]string, error) {
	var data ActionsData
	err := json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, err
	}
	return data.Actions, nil
}

func ExtractActionsAndFilterIP4(jsonData []byte) ([]string, error) {
	cidrs, err := ExtractActions(jsonData)
	if err != nil {
		return nil, err
	}
	return filterIP4Addresses(cidrs), nil
}

// Build the json Struct for the policy
type Policy struct {
	Version   string      `json:"Version"`
	Id        string      `json:"Id"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid       string    `json:"Sid"`
	Effect    string    `json:"Effect"`
	Principal string    `json:"Principal"`
	Action    string    `json:"Action"`
	Resource  string    `json:"Resource"`
	Condition Condition `json:"Condition"`
}

type Condition struct {
	NotIpAddress NotIpAddress `json:"NotIpAddress"`
}

type NotIpAddress struct {
	SourceIPs []string `json:"aws:SourceIp"`
}

// BuildDenyPolicy constructs a deny policy JSON document for the given list of IPs.

func BuildDenyPolicy(ips []string) ([]byte, error) {
	policy := Policy{
		Version: "2012-10-17",
		Id:      "GitHubActionsDenyPolicy",
		Statement: []Statement{
			{
				Sid:       "DenyNonGitHubActionsIPs",
				Effect:    "Deny",
				Principal: "*",
				Action:    "ecr:*",
				Resource:  "*",
				Condition: Condition{
					NotIpAddress: NotIpAddress{
						SourceIPs: ips,
					},
				},
			},
		},
	}
	return json.Marshal(policy)
}
