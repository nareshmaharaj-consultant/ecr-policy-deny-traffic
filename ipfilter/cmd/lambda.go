package main

import (
	"bytes"
	"context"
	"encoding/json"
	ipfilter "ipfilter/ipfilter/filter"

	"github.com/aws/aws-lambda-go/lambda"
)

// HOW to build this Lambda:
// GOOS=linux GOARCH=amd64 go build -o bootstrap ipfilter/cmd/lambda.go
// zip function.zip bootstrap

/*
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
*/

// Add the loggin role
/*
aws iam attach-role-policy \
  --role-name ipfilter-lambda-exec \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
*/

// Create the Lambda function
// Modern Go binaries run on AWS’s new “provided” runtime on AL2023.
// Go Lambda binaries must be named bootstrap
/*
aws lambda create-function \
  --function-name ipfilter-lambda \
  --handler bootstrap \
  --runtime provided.al2023 \
  --role arn:aws:iam::123456789012:role/ipfilter-lambda-exec \
  --zip-file fileb://function.zip \
  --architecture x86_64
*/

// GET the Lambda function
/*
aws lambda get-function --function-name ipfilter-lambda
*/

// UPDATE the Lambda function
/*
aws lambda update-function-code \
  --function-name ipfilter-lambda \
  --zip-file fileb://function.zip
*/
// Test the Lambda function
/*
aws lambda invoke \
  --function-name ipfilter-lambda \
  --payload '{"minify": true}' \
  output.json
*/

// Input structure for Lambda
type Input struct {
	Minify bool `json:"minify"`
}

type Output struct {
	Policy string `json:"policy"`
}

func handler(ctx context.Context, in Input) (json.RawMessage, error) {
	policy, err := ipfilter.GeneratePolicy(in.Minify)
	if err != nil {
		return nil, err
	}

	// If minified = true → return raw unformatted bytes
	if in.Minify {
		return json.RawMessage(policy), nil
	}

	// Otherwise → pretty format it
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, policy, "", "  "); err != nil {
		return nil, err
	}

	//return json.RawMessage(pretty.Bytes()), nil
	return pretty.Bytes(), nil
}

func mainX() {
	lambda.Start(handler)
}
