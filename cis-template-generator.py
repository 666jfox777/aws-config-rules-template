#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################################################################################
#
# Account Level Monitoring and Alarms with AWS Config Rules
# =========================================================
#
# This script is designed to generate a CloudFormation template that will implement a set of desired rules or policies
# on your AWS account. In order to do this it makes use of the following AWS technologies:
#
# - Lambda Functions
# - Config
# - Config Rules
#
# These technologies are used to enforce recommended configuration in the CIS Benchmarks for AWS. You can read the
# benchmarks here: https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf
#
# Because we understand that not everyone will want to implement every single one of these recommendations, you can
# easily control which ones are included by either removing or setting the rule to disabled in the CSV file provided.
#
# Contributions welcome, see links for the GitHub location.
#
# Links:
#   - For more details and discussion, see: https://justinfox.me/articles/aws-config-rules
#   - Source code is available on GitHub: https://github.com/666jfox777/aws-config-rules-template
#
# Dependencies:
#   - This project makes use of the Troposphere python library. You can install it with `pip install troposphere`.
#
########################################################################################################################


import sys
import time
import argparse
import csv
import os.path
import json
import zipfile
from itertools import islice
from troposphere.constants import NUMBER
from troposphere import GetAtt, Output, Parameter, Ref, Template
from troposphere.sns import Topic, Subscription
from troposphere.logs import MetricFilter, MetricTransformation
from troposphere.cloudwatch import Alarm, MetricDimension
from troposphere.iam import Role, Policy
from troposphere.awslambda import Function, Permission, Code
from troposphere.config import ConfigRule, Source, SourceDetails, Scope
import boto3


# Execute
# =======
#
# This function will take the resulting AWS CloudFormation template and AWS Lambda Function code and:
#
# 1) Upload the AWS Lambda Function zip file to a S3 bucket on your account
# 2) Create the AWS CloudFormation stack with the provided template
#
# This function will create AWS resources if they do not exist. Only use the '-e' option if you really want everything
# done for you. If you do not specify the '-e' option then instead the required commands will be printed to screen.
def execute(template, s3bucket, s3key, output, e=False):

    # If we are running this against an AWS account...
    if e:

        # Let's get a client running for S3 and for CloudFormation
        s3 = boto3.client('s3')
        s3_resource = boto3.resource('s3')
        cloudformation = boto3.client('cloudformation')

        # Package the AWS Lambda Function as a Zip File
        try:
            zip = zipfile.ZipFile('cf-cis-benchmarks-lambda-source.zip', 'w', compression=zipfile.ZIP_DEFLATED)
            zip.write('index.js')
            zip.close()
        except:
            print "An error occurred while attempting to generate a Zip File of the AWS Lambda code."
            raise
            exit(1)

        # Upload the Zip File to AWS S3
        try:
            s3_resource.meta.client.upload_file('./cf-cis-benchmarks-lambda-source.zip', s3bucket, '%s/cf-cis-benchmarks-lambda-source.zip' % (s3key))
        except:
            print "An error occurred while trying to upload the Lambda Zip File to AWS S3."
            exit(1)

        # Upload the CloudFormation template to S3
        try:
            cloudformation_response = s3.put_object( Body=b'%s' % template.to_json(), Bucket=s3bucket, Key='%s/%s' % (s3key, output) )
        except:
            print "An error occurred while trying to upload the AWS CloudFormation template to AWS S3."
            exit(1)

        # Try to create and/or update the CloudFormation stack...
        try:
            try:
                describe_response = cloudformation.describe_stacks(StackName='cf-cis-benchmarks')
                status = describe_response['Stacks'][0]['StackStatus']
            except:
                status = "DOES_NOT_EXIST"
            if status == "ROLLBACK_COMPLETE":
                delete_response = cloudformation.delete_stack( StackName='cf-cis-benchmarks' )
                print "Deleting broken stack..."
                time.sleep( 30 )
                create_response = cloudformation.create_stack(
                    StackName='cf-cis-benchmarks',
                    TemplateURL='https://s3.amazonaws.com/%s/%s/%s' % (s3bucket, s3key, output),
                    TimeoutInMinutes=10,
                    Capabilities=['CAPABILITY_IAM','CAPABILITY_NAMED_IAM']
                )
            elif status == "DOES_NOT_EXIST":
                create_response = cloudformation.create_stack(
                    StackName='cf-cis-benchmarks',
                    TemplateURL='https://s3.amazonaws.com/%s/%s/%s' % (s3bucket, s3key, output),
                    TimeoutInMinutes=10,
                    Capabilities=['CAPABILITY_IAM','CAPABILITY_NAMED_IAM']
                )
            else:
                update_response = cloudformation.update_stack(
                    StackName='cf-cis-benchmarks',
                    TemplateURL='https://s3.amazonaws.com/%s/%s/%s' % (s3bucket, s3key, output),
                    Capabilities=['CAPABILITY_IAM','CAPABILITY_NAMED_IAM']
                )
            print "See AWS CloudFormation for progress and status."
        except:
            print "A CloudFormation error was encountered."
            raise
            exit(1)
    else:
        # Print the template to JSON
        write_template(template.to_json(), output)
        print "Before launching or updating the stack via CloudFormation, ensure that you have uploaded the .zip containing the Lambda code to S3."
        print "s3://%s/%s" % (s3bucket,s3key)


# Write Template
# ==============
#
# This function will take the Troposphere json formatted AWS CloudFormation template and write it to disk for later
# inspection and/or uploading.
#
# Expects:
#
# 1) Troposphere json formatted string (valid CloudFormation template)
# 2) A destination file path (as a string)
#
# If the tool cannot write the template to disk, it will print an error and exit the application.
def write_template(template, destination):
    """
    """
    try:
        with open(destination, 'w') as file:
            file.write(template)
    except:
        print "Failed to write the template to disk: " + destination
        print "Use -h for usage information."
        exit(1)


# Add Lambda Function
# ===================
#
# A wrapper around creating a Lambda Function with the Troposphere library. Creates:
#
# - AWS IAM Role that AWS Lambda can assume (required for getting resource status and putting evaluations to AWS Config)
# - The AWS Lambda Function
# - The "Permission" for AWS Config to call your AWS Lambda Function
#
# These are appended to the list of resources passed to the function. The AWS Lambda Function Arn is also appended to a
# list of outputs.
#
# This function also expects the path to the Lambda zip file and the S3 details.
def add_lambda_function(resources, outputs, s3bucket, s3key):
    resources.append(
        Role(
            "LambdaConfigRulesRole",
            Path="/",
            Policies=[Policy(
                PolicyName="ReadOnlyForPerformingEvaluations",
                PolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": [
                            "acm:DescribeCertificate", "acm:GetCertificate", "acm:ListCertificates",
                            "autoscaling:Describe*",
                            "cloudformation:Describe*", "cloudformation:Get*", "cloudformation:List*",
                            "cloudfront:Get*", "cloudfront:List*",
                            "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:LookupEvents", "cloudtrail:ListTags", "cloudtrail:ListPublicKeys",
                            "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
                            "config:Deliver*", "config:Describe*", "config:Get*",
                            "dynamodb:BatchGetItem", "dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:ListTables", "dynamodb:Query", "dynamodb:Scan",
                            "ec2:Describe*", "ec2:GetConsoleOutput",
                            "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:GetManifest", "ecr:DescribeRepositories", "ecr:ListImages", "ecr:BatchGetImage",
                            "ecs:Describe*", "ecs:List*",
                            "elasticache:Describe*", "elasticache:List*",
                            "elasticloadbalancing:Describe*",
                            "elasticmapreduce:Describe*", "elasticmapreduce:List*",
                            "es:DescribeElasticsearchDomain", "es:DescribeElasticsearchDomains", "es:DescribeElasticsearchDomainConfig", "es:ListDomainNames", "es:ListTags", "es:ESHttpGet", "es:ESHttpHead",
                            "events:DescribeRule", "events:ListRuleNamesByTarget", "events:ListRules", "events:ListTargetsByRule", "events:TestEventPattern",
                            "firehose:Describe*", "firehose:List*",
                            "iam:GenerateCredentialReport", "iam:Get*", "iam:List*",
                            "inspector:Describe*", "inspector:Get*", "inspector:List*", "inspector:LocalizeText", "inspector:PreviewAgentsForResourceGroup",
                            "kinesis:Describe*", "kinesis:Get*", "kinesis:List*",
                            "kms:Describe*", "kms:Get*", "kms:List*",
                            "lambda:List*", "lambda:Get*",
                            "logs:Describe*", "logs:Get*", "logs:TestMetricFilter",
                            "rds:Describe*", "rds:ListTagsForResource",
                            "redshift:Describe*", "redshift:ViewQueriesInConsole",
                            "s3:Get*", "s3:List*",
                            "ses:Get*", "ses:List*",
                            "sns:Get*", "sns:List*",
                            "sqs:GetQueueAttributes", "sqs:ListQueues", "sqs:ReceiveMessage",
                            "tag:Get*",
                            "trustedadvisor:Describe*"
                          ],
                        "Resource": "*",
                        "Effect": "Allow"
                    }]
                }), Policy(
                PolicyName="CloudWatchLogs-FullAccess",
                PolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": ["logs:*"],
                        "Resource": "arn:aws:logs:*:*:*",
                        "Effect": "Allow"
                    }]
                }), Policy(
                PolicyName="AwsConfigRules-PutEvaluations",
                PolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": ["config:Put*"],
                        "Resource": "*",
                        "Effect": "Allow"
                    }]
                })],
            AssumeRolePolicyDocument={"Version": "2012-10-17", "Statement": [ {"Action": ["sts:AssumeRole"], "Effect": "Allow", "Principal": {"Service": ["lambda.amazonaws.com"]}}]},
        )
    )
    resources.append(
        Function(
            "LambdaConfigRulesFunction",
            Code=Code( S3Bucket=s3bucket, S3Key='%s/cf-cis-benchmarks-lambda-source.zip' % (s3key) ),
            Handler="index.handler",
            Role=GetAtt("LambdaConfigRulesRole", "Arn"),
            Runtime="nodejs6.10",
            Timeout=10
        )
    )
    resources.append(
        Permission(
            "LambdaConfigRulesPermission",
            DependsOn="LambdaConfigRulesFunction",
            Action="lambda:InvokeFunction",
            FunctionName=GetAtt("LambdaConfigRulesFunction", "Arn"),
            Principal="config.amazonaws.com",
            SourceAccount=Ref("AWS::AccountId")
        )
    )
    outputs.append(
        Output(
            "LambdaConfigRulesFunctionArn",
            Value=GetAtt("LambdaConfigRulesFunction", "Arn"),
            Description="Amazon resource identifier or ARN for the Lambda Function."
        )
    )
    return resources, outputs


def add_config_rule(resources, item):
    if item['Scope'] == 'Global':
        resources.append(
            ConfigRule(
                item['Name'],
                DependsOn=["LambdaConfigRulesFunction", "LambdaConfigRulesPermission"],
                ConfigRuleName=item['Name'],
                Description=item['Description'],
                InputParameters=item['InputParameters'],
                Scope=Scope(),
                Source=Source(
                    Owner=item['Owner'],
                    SourceDetails=[
                        SourceDetails(
                            EventSource="aws.config",
                            MessageType=item['MessageType']
                        )
                    ],
                    SourceIdentifier=GetAtt("LambdaConfigRulesFunction", "Arn")
                )
            )
        )
    else:
        resources.append(
            ConfigRule(
                item['Name'],
                DependsOn=["LambdaConfigRulesFunction", "LambdaConfigRulesPermission"],
                ConfigRuleName=item['Name'],
                Description=item['Description'],
                InputParameters=item['InputParameters'],
                Scope=Scope(
                    ComplianceResourceTypes=[item['Scope']]
                ),
                Source=Source(
                    Owner=item['Owner'],
                    SourceDetails=[
                        SourceDetails(
                            EventSource="aws.config",
                            MessageType=item['MessageType']
                        )
                    ],
                    SourceIdentifier=GetAtt("LambdaConfigRulesFunction", "Arn")
                )
            )
        )
    return resources;


def add_cloudwatch_alarm(resources, item):
    resources.append(
        Alarm(
            item['Name']+"Alarm",
            AlarmName=item['Name']+"Alarm",
            AlarmDescription=item['AlarmDescription'],
            Namespace=item['MetricNameSpace'],
            MetricName=item['MetricName'],
            Statistic=item['Statistic'],
            Period=item['Period'],
            EvaluationPeriods=item['EvaluationPeriods'],
            Threshold=item['Threshold'],
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            AlarmActions=[]
        )
    )
    return resources


def add_cloudwatch_metric(resources, item):
    resources.append(
        MetricFilter(
            item['Name']+"MetricFilter",
            FilterPattern=item['FilterPattern'],
            LogGroupName=item['LogGroup'],
            MetricTransformations=[MetricTransformation(
                MetricName=item['MetricName'],
                MetricNamespace=item['MetricNameSpace'],
                MetricValue="1"
            )]
        )
    )
    return resources


def add_sns_topic(resources, outputs):
    resources.append(
        Topic(
            "BenchmarksNotificationTopic",
            DisplayName="CIS-Benchmarks",
            TopicName="CIS-Benchmarks"
        )
    )
    return resources, outputs


def generate_template(accountalarms, configrules, s3bucket, s3key):
    parameters = []
    maps = []
    resources = []
    outputs = []
    conditions = {}

    resources, outputs = add_sns_topic(resources, outputs)

    for item in accountalarms:
        if item['Type'].strip() == 'CloudTrail':
            resources = add_cloudwatch_metric(resources, item)
            resources = add_cloudwatch_alarm(resources, item)

    resources, outputs = add_lambda_function(resources, outputs, s3bucket, s3key)

    for item in configrules:
        resources = add_config_rule(resources, item)

    template = Template()
    template.add_version('2010-09-09')
    template.add_description(
        "This is an AWS CloudFormation template that provisions metric filters"
        " based on a spreadsheet of applicable metric filters."
        " ***WARNING*** "
        "This template creates many Amazon CloudWatch alarms based on a Amazon"
        " CloudWatch Logs Log Group. You will be billed for the AWS resources "
        "used if you create a stack from this template."
    )
    [template.add_parameter(p) for p in parameters]
    [template.add_condition(k, conditions[k]) for k in conditions]
    [template.add_resource(r) for r in resources]
    [template.add_output(o) for o in outputs]
    return template


def process_configrules(file):
    configuration = []
    if os.path.isfile(file):
        with open(file, 'rbU') as f:
            reader = csv.reader(f)
            try:
                for row in islice(reader, 1, None):
                    configuration.append( { 'Name': row[0].strip(), 'Type': row[1].strip(), 'Description': row[2].strip(), 'Owner': row[3].strip(), 'MessageType': row[4].strip(), 'Scope': row[5].strip(), 'MaximumExecutionFrequency': row[6].strip(), 'InputParameters': json.loads(row[7].replace("|", ",").strip()) } )
            except csv.Error as e:
                sys.exit('file %s, line %d: %s' % (VPC_ID, reader.line_num, e))
    else:
        print "File does not exist: %s" % (file)
        print "Use -h for usage information."
        exit(1)
    return configuration


def process_accountalarms(file):
    configuration = []
    if os.path.isfile(file):
        with open(file, 'rbU') as f:
            reader = csv.reader(f)
            try:
                for row in islice(reader, 1, None):
                    configuration.append( { 'Name': row[0], 'Type': row[1], 'LogGroup': row[2], 'FilterPattern': row[3], 'MetricNameSpace': row[5], 'MetricName': row[4], 'EvaluationPeriods': row[6], 'Period': row[7], 'Statistic': row[8], 'Threshold': row[9], 'AlarmDescription': row[10], 'Paging': row[11] } )
            except csv.Error as e:
                sys.exit('file %s, line %d: %s' % (VPC_ID, reader.line_num, e))
    else:
        print "File does not exist: %s" % (file)
        print "Use -h for usage information."
        exit(1)
    return configuration


# Main Program
# ============
#
# The main program parses the passed arguments, calls the functions to generate the AWS CloudFormation template and AWS
# Lambda Function zip file, and optionally uploads the files and creates the CloudFormation stack. There are basically
# two modes to run this tool:
#
# 1) Generate templates and files on the local disk only
# 2) Generate templates and files and upload them to AWS and create the AWS resources
#
# Depending
def main(argv):

    # Tool description, displayed when a "-h" flag is presented.
    parser = argparse.ArgumentParser(
        description=''
        'This tool generates a CloudFormation template that can provision: a Lambda Function, CloudWatch Metrics, '
        'CloudWatch Alarms, and Config Rules. The example templates provided with the tool target adding or modifying '
        ' the required components for achieving high CIS benchmark scores for AWS.'
    )

    # Add required arguments
    # Add optional arguments for template generation
    parser.add_argument( "-f", "--file",      help="The path to the CSV formatted file that contains the configuration of CloudWatch Metrics and Alarms.", required=False )
    parser.add_argument( "-i", "--input",     help="The path to the CSV formatted file that contains the configuration of the Lambda functions and Config Rules.", required=False )
    parser.add_argument( "-o", "--output",    help="The local output destination for the CloudFormation template and Lambda zip files. Defaults to the current working directory.", required=False )

    # Add optional arguments for execution against AWS
    parser.add_argument( "-e", "--execute",   help="A boolean flag that controls whether to execute the stack against an AWS account.", default=False, required=False )
    parser.add_argument( "-b", "--s3bucket",  help="The AWS S3 Bucket used to store the CloudFormation template and related AWS stack resources.", required=False )
    parser.add_argument( "-k", "--s3key",     help="The AWS S3 file path for where to store the files in the S3 bucket. If not supplied the root of the bucket will be used.", required=False )

    # Other optional arguments.
    parser.add_argument( "-v", "--verbose",   help="Increase the logging output verbosity level.", action="store_true" )

    # Parse the arguments that have been provided.
    args = parser.parse_args()

    # Verify / set required variables.
    accountalarms = args.file or "accountalarms.csv"
    configrules = args.input or "configrules.csv"
    output = args.output or "cis-benchmarks.template"
    s3bucket = args.s3bucket or "justinfox"
    s3key = args.s3key or "example"

    # Access the source CSV and grab the metric and alert configuration.
    accountalarms = process_accountalarms(accountalarms)

    # Access the source CSV and grab the Lambda and Config Rules configuration.
    configrules = process_configrules(configrules)

    # Iterate through the configuration and generate the template
    template = generate_template( accountalarms, configrules, s3bucket, s3key )

    # Write the template to disk or against an AWS environment.
    execute(template, s3bucket, s3key, output, args.execute )


# Default execution path.
if __name__ == "__main__":
    main(sys.argv)
