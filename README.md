# aws-config-rules-template

This repository contains a collection of AWS Config Rules examples for applying the CIS Benchmarks for AWS.
This repository is provided in concert to the following article:
[Advanced Auditing with AWS Config](https://justinfox.me/articles/aws-config-rules)

## Overview

Does your AWS account comply with your security policies? How do you know? How do you track the state of resources, or
alert, or even automatically remediate issues? This repository and it's corresponding article discuss the usage of AWS
Config Rules to track resource changes and apply custom rules against the resources on your account. In particular,
the article takes a look at a few examples of the recommended benchmarks for your AWS account from the Center for
Internet Security.

## Usage

Generally, you can just run the default rulesets with `./cis-template-generator.py`.
But for more advanced usage:

````
$ ./cis-template-generator.py -h
usage: cis-template-generator.py [-h] [-f FILE] [-i INPUT] [-l AWSLAMBDA]
                                 [-o OUTPUT] [-e EXECUTE] [-p PROFILE]
                                 [-r REGION] [-b S3BUCKET] [-k S3KEY] [-v]

This tool generates a CloudFormation template that can provision: a Lambda
Function, CloudWatch Metrics, CloudWatch Alarms, and Config Rules. The example
templates provided with the tool target adding or modifying the required
components for achieving high CIS benchmark scores for AWS.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The path to the CSV formatted file that contains the
                        configuration of CloudWatch Metrics and Alarms.
  -i INPUT, --input INPUT
                        The path to the CSV formatted file that contains the
                        configuration of the Lambda functions and Config
                        Rules.
  -l AWSLAMBDA, --awslambda AWSLAMBDA
                        The path to the Lambda Function code base.
  -o OUTPUT, --output OUTPUT
                        The local output destination for the CloudFormation
                        template and Lambda zip files. Defaults to the current
                        working directory.
  -e EXECUTE, --execute EXECUTE
                        A boolean flag that controls whether to execute the
                        stack against an AWS account.
  -p PROFILE, --profile PROFILE
                        The AWS profile to use for the AWS SDK.
  -r REGION, --region REGION
                        The AWS region to use for the AWS SDK. Note: while
                        much of what will be executed is region agnostic, this
                        will set where the S3 buckets, CloudFormation stacks,
                        and Config Rules are found.
  -b S3BUCKET, --s3bucket S3BUCKET
                        The AWS S3 Bucket used to store the CloudFormation
                        template and related AWS stack resources.
  -k S3KEY, --s3key S3KEY
                        The AWS S3 file path for where to store the files in
                        the S3 bucket. If not supplied the root of the bucket
                        will be used.
  -v, --verbose         Increase the logging output verbosity level.
````


