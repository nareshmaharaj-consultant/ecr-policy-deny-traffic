# IP Filter - GitHub Actions to AWS ECR Policy Generator

A powerful Go tool that fetches GitHub Actions IP ranges and generates AWS IAM deny policies to restrict ECR access to only authorized GitHub Actions runners.

## 🎯 Overview

**IP Filter** provides two distinct entry points for the same core functionality:

1. **CLI Tool** (`ipfilter.go`) - Command-line application for local policy generation
2. **AWS Lambda** (`lambda.go`) - Serverless function for automated, cloud-native policy generation

Both tools leverage the same filtering and policy generation logic, making it easy to generate deny policies for GitHub Actions IP ranges in any environment.

## 🏗️ Architecture

### Dual-Entry Design

The project is organized with two main entry points in `ipfilter/cmd/`:

```
ipfilter/cmd/
├── ipfilter.go         # CLI tool entry point
├── lambda.go           # AWS Lambda handler entry point
├── ipfilter_test.go    # CLI and filtering tests
└── *Note: Only ONE main() function can be active at build time*
```

**Why two mains?**
- The CLI uses `Xmain()` (prefixed with `X`) to avoid conflicts with Lambda's `main()`
- When building the CLI, rename `Xmain()` → `main()`
- When building Lambda, the `main()` in `lambda.go` is used
- This allows 100% code reuse without conditional compilation

### Core Filtering Logic

All the heavy lifting happens in `ipfilter/filter/`:

| File | Purpose |
|------|---------|
| `filter.go` | Core policy building, JSON marshaling, and reordering |
| `filter_utils.go` | HTTP utilities for fetching GitHub metadata |
| `policy_generator.go` | Orchestrates the entire policy generation pipeline |
| `filter_test.go` | Comprehensive test coverage for filtering logic |

## 📋 How It Works

### Step 1: Fetch GitHub Metadata
The tool calls `https://api.github.com/meta` to retrieve GitHub's public IP ranges, including Actions runners.

```go
rawData, _ := ipfilter.FetchURL("https://api.github.com/meta")
```

### Step 2: Extract & Filter
Extracts the `actions` field and filters for IPv4 CIDR blocks (excludes IPv6).

```go
ipfiltered, _ := ipfilter.ExtractActionsAndFilterIP4(rawData)
```

### Step 3: Generate AWS Policy
Builds a deny policy that blocks all traffic EXCEPT from allowed GitHub Actions IPs:

```json
{
  "Version": "2012-10-17",
  "Id": "GitHubActionsDenyPolicy1",
  "Statement": [
    {
      "Sid": "DenyNonGitHubActionsIPs",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "ecr:*",
      "Resource": "*",
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": ["140.82.112.0/20", "143.55.64.0/20", ...]
        }
      }
    }
  ]
}
```

### Step 4: Output
- **CLI**: Writes formatted JSON to file or stdout
- **Lambda**: Returns policy as JSON response with optional minification

## 🚀 Quick Start

### Option 1: CLI Tool

**Build:**
```bash
go build -o ipfilter-bin ./ipfilter/cmd/ipfilter.go
```
> **Note:** Requires renaming `Xmain()` to `main()` in `ipfilter.go` first

**Usage:**
```bash
# Generate policy to file (pretty-printed)
./ipfilter-bin --source github --output policy.json

# Generate policy to stdout (minified)
./ipfilter-bin --source github --minify

# Quiet mode (errors only)
./ipfilter-bin --source github --output policy.json --quiet
```

**CLI Flags:**
- `--source` (string): IP source provider, currently only `github` supported (default: `github`)
- `--output` (string): Output file path; if empty, prints to stdout (default: `policy.json`)
- `--minify` (bool): Minify output JSON (default: `false`)
- `--quiet` (bool): Suppress non-error logging (default: `false`)

### Option 2: AWS Lambda

**Build:**
```bash
GOOS=linux GOARCH=amd64 go build -o bootstrap ./ipfilter/cmd/lambda.go
zip function.zip bootstrap
```

**Setup Lambda Role:**
```bash
aws iam create-role \
  --role-name ipfilter-lambda-exec \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": { "Service": "lambda.amazonaws.com" },
        "Action": "sts:AssumeRole"
      }
    ]
  }'

aws iam attach-role-policy \
  --role-name ipfilter-lambda-exec \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

**Create Lambda Function:**
```bash
aws lambda create-function \
  --function-name ipfilter-lambda \
  --handler bootstrap \
  --runtime provided.al2023 \
  --role arn:aws:iam::123456789012:role/ipfilter-lambda-exec \
  --zip-file fileb://function.zip \
  --architecture x86_64
```

**Invoke Function:**
```bash
# Return pretty-printed policy
aws lambda invoke \
  --function-name ipfilter-lambda \
  --payload '{"minify": false}' \
  policy.json

# Return minified policy
aws lambda invoke \
  --function-name ipfilter-lambda \
  --payload '{"minify": true}' \
  policy.json
```

**Update Function Code:**
```bash
aws lambda update-function-code \
  --function-name ipfilter-lambda \
  --zip-file fileb://function.zip
```

## 📦 Project Structure

```
.
├── README.md                           # This file
├── go.mod                              # Module dependencies
├── go.sum                              # Dependency checksums
├── bootstrap                           # Lambda bootstrap executable (after build)
├── function.zip                        # Lambda deployment package
├── output.json                         # Sample Lambda output
│
├── .github/workflows/
│   └── test-and-build-app.yml          # GitHub Actions CI/CD pipeline
│
├── ipfilter/
│   ├── cmd/
│   │   ├── ipfilter.go                 # ✅ CLI entry point (Xmain)
│   │   ├── lambda.go                   # ✅ Lambda handler entry point (main)
│   │   └── ipfilter_test.go            # Tests for both CLI & filtering
│   │
│   ├── filter/
│   │   ├── filter.go                   # Core policy generation
│   │   ├── filter_utils.go             # HTTP utilities
│   │   ├── policy_generator.go         # Pipeline orchestrator
│   │   ├── filter_test.go              # Filter logic tests
│   │   └── raw-data.json               # Sample GitHub metadata (for testing)
│   │
│   └── raw-data.json                   # Test fixture for GitHub metadata
│
├── app/
│   └── ipfilter-bin                    # CLI binary (after build)
│
└── .vscode/                            # VS Code workspace settings
```

## 🧪 Testing

Run all tests with coverage:
```bash
go test -v -race -coverprofile=coverage.out ./...
```

View coverage report:
```bash
go tool cover -html=coverage.out
```

Run specific test:
```bash
go test -run TestExtractActionsAndFilterIP4 -v
```

## 🔧 Dependencies

- **Go 1.21.3+**
- **AWS Lambda Go SDK** (`github.com/aws/aws-lambda-go`) - Used only by Lambda handler

## 📝 GitHub Actions CI/CD

The repository includes an automated workflow (`.github/workflows/test-and-build-app.yml`) that:

✅ Runs on every push to `main` and all pull requests  
✅ Executes full test suite with race detection  
✅ Collects code coverage and uploads to Codecov  
✅ Builds both CLI and Lambda artifacts  
✅ Uploads binaries as workflow artifacts  

## 🎓 Key Concepts

### Why GitHub Actions IP Filtering?

GitHub Actions runners have dynamic, publicly known IP ranges. By creating an ECR repository policy that **denies** all traffic except from these IPs, you ensure:

- ✅ Only legitimate GitHub Actions workflows can push/pull from ECR
- ✅ External actors cannot compromise your images
- ✅ Policy stays current via automation

### IPv4-Only Design

The tool filters for IPv4 CIDR blocks because AWS IAM policies commonly reference IPv4 addresses. IPv6 support can be added if needed.

### JSON Reordering

AWS IAM policies don't care about key order, but the tool reorders to a standard format (`Version` → `Id` → `Statement`) for readability and consistency.

## 🚦 Status & Future

- **Current:** Supports GitHub Actions IP ranges only
- **Roadmap:** 
  - GitLab Runner support
  - Bitbucket Pipelines support
  - Scheduled Lambda updates via EventBridge
  - Multi-region ECR policy generation

## 📄 License

[Add your license here]

## 🤝 Contributing

[Add contribution guidelines here]

---

**Questions?** Open an issue or check the test files for usage examples.
