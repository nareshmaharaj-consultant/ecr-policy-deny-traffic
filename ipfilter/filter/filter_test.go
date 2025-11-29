package ipfilter

import (
	"encoding/json"
	"testing"
)

func TestIP4Filter(t *testing.T) {
	test_ips := []string{
		"140.82.112.0/20",
		"2606:50c0:8000::/36", // IPv6
		"143.55.64.0/20",
	}

	got := filterIP4Addresses(test_ips)

	want := []string{
		"140.82.112.0/20",
		"143.55.64.0/20",
	}

	if len(want) != len(got) {
		t.Fatalf("Expected %d IPs, but got %d IPs", len(want), len(got))
	}

	for i, ip := range got {
		if ip != want[i] {
			t.Errorf("Expected IP %s, but got %s", ip, got[i])
		}
	}
}

func TestExtractActionsCIDRs(t *testing.T) {
	jsonData := []byte(`{
		"verifiable_password_authentication": false,
		"ssh_key_fingerprints": {
			"SHA256_ECDSA": "p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
			"SHA256_ED25519": "+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
			"SHA256_RSA": "uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"
		},
		"ssh_keys": [
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
			"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk="
		],
		"hooks": [
			"192.30.252.0/22"
		],
		"web": [
			"192.30.252.0/22"
		],
		"api": [
			"192.30.252.0/22",
			"185.199.108.0/22"
		],
		"git": [
			"192.30.252.0/22",
			"185.199.108.0/22"
		],
		"github_enterprise_importer": [
			"192.30.252.0/22",
			"185.199.108.0/22"
		],
		"packages": [
			"140.82.121.33/32",
			"140.82.121.34/32"
		],
		"pages": [
			"192.30.252.153/32",
			"2606:50c0:8001::153/128",
			"2606:50c0:8002::153/128",
			"2606:50c0:8003::153/128"
		],
		"importer": [
			"52.23.85.212/32",
			"172.184.222.112/28"
		],
		"actions": [
			"4.148.0.0/16",
			"4.149.0.0/18",
			"2a01:111:f403:d91b::/64",
			"2a01:111:f403:d91c::/64",
			"2a01:111:f403:da00::/64",
			"2a01:111:f403:da01::/64"
		],
		"actions_macos": [
			"13.105.117.0/24",
			"13.105.220.0/25"
		],
		"codespaces": [
			"20.42.11.16/28",
			"172.210.54.224/28"
		],
		"copilot": [
			"192.30.252.0/22",
			"185.199.108.0/22",
			"140.82.112.0/20",
			"143.55.64.0/20"
		],
		"domains": {
			"website": [
			"*.github.com",
			"*.github.dev",
			"*.github.io",
			"*.githubassets.com",
			"*.githubusercontent.com"
			],
			"codespaces": [
			"*.github.com",
			"*.api.github.com",
			"*.azureedge.net",
			"*.github.dev",
			"*.msecnd.net",
			"*.visualstudio.com",
			"*.vscode-webview.net",
			"*.windows.net",
			"*.microsoft.com"
			],
			"copilot": [
			"*.github.com",
			"*.githubusercontent.com",
			"default.exp-tas.com",
			"*.githubcopilot.com"
			],
			"packages": [
			"mavenregistryv2prod.blob.core.windows.net",
			"npmregistryv2prod.blob.core.windows.net",
			"nugetregistryv2prod.blob.core.windows.net",
			"rubygemsregistryv2prod.blob.core.windows.net",
			"npm.pkg.github.com"
			],
			"actions": [
			"*.actions.githubusercontent.com",
			"productionresultssa0.blob.core.windows.net",
			"productionresultssa1.blob.core.windows.net"
			],
			"actions_inbound": {
			"full_domains": [
				"github.com",
				"api.github.com"
			],
			"wildcard_domains": [
				"*.githubusercontent.com",
				"*.core.windows.net"
			]
			},
			"artifact_attestations": {
			"trust_domain": "",
			"services": [
				"*.actions.githubusercontent.com",
				"tuf-repo.github.com",
				"fulcio.githubapp.com",
				"timestamp.githubapp.com"
			]
			}
	   	   }
		}`)

	got, err := ExtractActions(jsonData)

	want := []string{
		"4.148.0.0/16",
		"4.149.0.0/18",
		"2a01:111:f403:d91b::/64",
		"2a01:111:f403:d91c::/64",
		"2a01:111:f403:da00::/64",
		"2a01:111:f403:da01::/64",
	}

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(want) != len(got) {
		t.Fatalf("Expected %d CIDRs, but got %d CIDRs", len(want), len(got))
	}

	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Expected CIDR %s, but got %s", want[i], got[i])
		}
	}
}

func TestExtractActionsAndFilterIP4(t *testing.T) {
	jsonData := []byte(`{
		"verifiable_password_authentication": false,
		"ssh_key_fingerprints": {
			"SHA256_ECDSA": "p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
			"SHA256_ED25519": "+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
			"SHA256_RSA": "uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"
		},
		"ssh_keys": [
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
			"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk="
		],
		"hooks": [
			"192.30.252.0/22"
		],
		"web": [
			"192.30.252.0/22"
		],
		"api": [
			"192.30.252.0/22",
			"185.199.108.0/22"
		],
		"git": [
			"192.30.252.0/22",
			"185.199.108.0/22"
		],
		"github_enterprise_importer": [
			"192.30.252.0/22",
			"185.199.108.0/22"
		],
		"packages": [
			"140.82.121.33/32",
			"140.82.121.34/32"
		],
		"pages": [
			"192.30.252.153/32",
			"2606:50c0:8001::153/128",
			"2606:50c0:8002::153/128",
			"2606:50c0:8003::153/128"
		],
		"importer": [
			"52.23.85.212/32",
			"172.184.222.112/28"
		],
		"actions": [
			"4.148.0.0/16",
			"4.149.0.0/18",
			"2a01:111:f403:d91b::/64",
			"2a01:111:f403:d91c::/64",
			"2a01:111:f403:da00::/64",
			"2a01:111:f403:da01::/64"
		],
		"actions_macos": [
			"13.105.117.0/24",
			"13.105.220.0/25"
		],
		"codespaces": [
			"20.42.11.16/28",
			"172.210.54.224/28"
		],
		"copilot": [
			"192.30.252.0/22",
			"185.199.108.0/22",
			"140.82.112.0/20",
			"143.55.64.0/20"
		],
		"domains": {
			"website": [
			"*.github.com",
			"*.github.dev",
			"*.github.io",
			"*.githubassets.com",
			"*.githubusercontent.com"
			],
			"codespaces": [
			"*.github.com",
			"*.api.github.com",
			"*.azureedge.net",
			"*.github.dev",
			"*.msecnd.net",
			"*.visualstudio.com",
			"*.vscode-webview.net",
			"*.windows.net",
			"*.microsoft.com"
			],
			"copilot": [
			"*.github.com",
			"*.githubusercontent.com",
			"default.exp-tas.com",
			"*.githubcopilot.com"
			],
			"packages": [
			"mavenregistryv2prod.blob.core.windows.net",
			"npmregistryv2prod.blob.core.windows.net",
			"nugetregistryv2prod.blob.core.windows.net",
			"rubygemsregistryv2prod.blob.core.windows.net",
			"npm.pkg.github.com"
			],
			"actions": [
			"*.actions.githubusercontent.com",
			"productionresultssa0.blob.core.windows.net",
			"productionresultssa1.blob.core.windows.net"
			],
			"actions_inbound": {
			"full_domains": [
				"github.com",
				"api.github.com"
			],
			"wildcard_domains": [
				"*.githubusercontent.com",
				"*.core.windows.net"
			]
			},
			"artifact_attestations": {
			"trust_domain": "",
			"services": [
				"*.actions.githubusercontent.com",
				"tuf-repo.github.com",
				"fulcio.githubapp.com",
				"timestamp.githubapp.com"
			]
			}
		}
		}`)

	got, err := ExtractActionsAndFilterIP4(jsonData)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	want := []string{
		"4.148.0.0/16",
		"4.149.0.0/18",
	}

	if len(want) != len(got) {
		t.Fatalf("Expected %d CIDRs, but got %d CIDRs", len(want), len(got))
	}

	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Expected CIDR %s, but got %s", want[i], got[i])
		}
	}
}

func TestBuildDenyPolicy(t *testing.T) {
	ips := []string{
		"140.82.112.0/20",
		"143.55.64.0/20",
	}

	policyBytes, err := BuildDenyPolicy(ips)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// t.Log(string(policyBytes))

	var doc Policy
	err = json.Unmarshal(policyBytes, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal policy JSON: %v", err)
	}

	if doc.Version != "2012-10-17" {
		t.Fatalf("wrong version: %s", doc.Version)
	}

	if len(doc.Statement) != 1 {
		t.Fatalf("Expected 1 statement in policy, but got %d", len(doc.Statement))
	}

	statement := doc.Statement[0]
	if statement.Effect != "Deny" {
		t.Errorf("Expected Effect to be 'Deny', but got '%s'", statement.Effect)
	}

	if len(statement.Condition.NotIpAddress.SourceIPs) != len(ips) {
		t.Fatalf("CIDR length mismatch")
	}

	PolicyMatch := `{"Version":"2012-10-17","Id":"GitHubActionsDenyPolicy","Statement":[{"Sid":"DenyNonGitHubActionsIPs","Effect":"Deny","Principal":"*","Action":"ecr:*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":["140.82.112.0/20","143.55.64.0/20"]}}}]}`
	if string(policyBytes) != PolicyMatch {
		t.Errorf("Policy JSON does not match expected structure.\nGot: %s\nWant: %s", string(policyBytes), PolicyMatch)
	}

}
