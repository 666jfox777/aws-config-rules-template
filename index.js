// This really needs a refactor, but leaving as-is.
var aws    = require('aws-sdk');
var s3     = new aws.S3();
var ec2     = new aws.EC2();
var zlib   = require('zlib');
var config = new aws.ConfigService();
var iam    = new aws.IAM();
var iamMaxPasswordAge = 90;


// Helper function used to validate input
function checkDefined(reference, referenceName) {
    if (!reference) {
        console.log("Error: " + referenceName + " is not defined");
        throw referenceName;
    }
    return reference;
}


// Reads and parses the ConfigurationSnapshot from the S3 bucket where Config is set up to deliver
function readSnapshot(s3client, s3key, s3bucket, callback) {
    var params = { Key: s3key, Bucket: s3bucket };
    var buffer = "";
    s3client.getObject(params)
        .createReadStream()
        .pipe(zlib.createGunzip())
        .on('data', function(chunk) { buffer = buffer + chunk; })
        .on('end', function() { callback(null, JSON.parse(buffer)); })
        .on('error', function(err) { callback(err, null); });
}


// Extract the account ID from the event
function getAccountId(invokingEvent) {
    checkDefined(invokingEvent, "invokingEvent");
    checkDefined(invokingEvent.s3ObjectKey, "invokingEvent.s3ObjectKey");
    var accountIdPattern = /AWSLogs\/(\d+)\/Config/;
    return accountIdPattern.exec(invokingEvent.s3ObjectKey)[1];
}


// Check whether the the resource has been deleted. If it has, then the evaluation is unnecessary.
function isApplicable(configurationItem, event) {
    checkDefined(configurationItem, "configurationItem");
    checkDefined(event, "event");
    var status = configurationItem.configurationItemStatus;
    var eventLeftScope = event.eventLeftScope;
    return ('OK' === status || 'ResourceDiscovered' === status) && false === eventLeftScope;	
}


// Publishes the evaluation results to the config rules service.
function putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp){
    var evaluation = {
        ComplianceResourceType: resourceType,
        ComplianceResourceId: resourceId,
        ComplianceType: compliance,
        OrderingTimestamp: orderingTimestamp
    };
    console.log("Evaluation complete:\n", JSON.stringify(evaluation));
    var putEvaluationsRequest = {
       Evaluations: [ evaluation ],
       ResultToken: event.resultToken
    };
    config.putEvaluations(putEvaluationsRequest, function (err, data) {
        if (err) { context.fail(err); } else { context.succeed(data); }
    });
}


// This is the handler that's invoked by Lambda
exports.handler = function(event, context) {
    console.log("Request received:\n", JSON.stringify(event));
    console.log("Context received:\n", JSON.stringify(context));
    checkDefined(event, "event");
    var invokingEvent = JSON.parse(event.invokingEvent);
    var ruleParameters = JSON.parse(event.ruleParameters);
    var configrule = ruleParameters.configrule;
    var orderingTimestamp = invokingEvent.notificationCreationTime;

    switch (configrule) {
        case 'CloudTrailIsEnabled':
            evaluateCloudTrailIsEnabled( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'CloudTrailLogFileValidationEnabled':
            evaluateCloudTrailLogFileValidationEnabled( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'CloudTrailS3BucketNotPublic':
            evaluateCloudTrailS3BucketNotPublic( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'CloudTrailWithCloudWatchLogsIsEnabled':
            evaluateCloudTrailWithCloudWatchLogsIsEnabled( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'CloudTrailLogsEncrypted':
            evaluateCloudTrailLogsEncrypted( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'ConfigIsEnabled':
            evaluateConfigIsEnabled( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'S3BucketAccessLoggingIsEnabled':
            evaluateS3BucketAccessLoggingIsEnabled( event, context, resourceType, resourceId, orderingTimestamp );
            break;
        case 'CustomerManagedKeyRotationIsEnabled':
            evaluateCustomerManagedKeyRotationIsEnabled( event, context, resourceType, resourceId, orderingTimestamp );
            break;
        case 'IamUnusedCredentialsAreDisabled':
            evaluateIamUnusedCredentialsAreDisabled( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp, ruleParameters );
            break;
        case 'IamCredentialRotation':
            evaluateIamCredentialRotation( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp, ruleParameters );
            break;
        case 'IamRequireLowercaseCharacters':
            evaluateIamRequireLowercaseCharacters( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'IamRequireUppercaseCharacters':
            evaluateIamRequireUppercaseCharacters( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'IamRequireSymbols':
            evaluateIamRequireSymbols( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'IamRequireNumbers':
            evaluateIamRequireNumbers( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp);
            break;
        case 'IamPasswordExpiryIsEnabled':
            evaluateIamPasswordExpiryIsEnabled( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp, ruleParameters );
            break;
        case 'IamPasswordReusePrevention':
            evaluateIamPasswordReusePrevention( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp, ruleParameters );
            break;
        case 'IamNoRootAccessKeys':
            evaluateIamNoRootAccessKeys( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'IamRootHardwareMfaIsEnabled':
            evaluateIamRootHardwareMfaIsEnabled( event, context, "AWS::::Account", getAccountId(invokingEvent), orderingTimestamp );
            break;
        case 'IamUsersMfaIsEnabled':
            evaluateIamUsersMfaIsEnabled( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp );
            break;
        case 'IamPoliciesAttachedGroupsOnly':
            evaluateIamPoliciesAttachedGroupsOnly( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp );
            break;
        case 'SecurityGroupsGlobalPort22':
            evaluateSecurityGroups( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp, ruleParameters );
            break;
        case 'SecurityGroupsGlobalPort3389':
            evaluateSecurityGroups( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp, ruleParameters );
            break;
        case 'SecurityGroupsDefaultDisablesTraffic':
            evaluateSecurityGroupsDefaultDisablesTraffic( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp, ruleParameters );;
            break;
        case 'VpcFlowLoggingIsEnabled':
            evaluateVpcFlowLoggingIsEnabled( event, context, invokingEvent.configurationItem.resourceType, invokingEvent.configurationItem.resourceId, orderingTimestamp );
            break;
        default:
            context.fail('Error, event not identified:', configrule);
    }
};


/*******************************************************************************
 * 
 * This section contains all of the various actual checks that are executed
 * by AWS Config Rules. This includes:
 * 
 * -+ CloudTrailIsEnabled
 * -+ CloudTrailLogFileValidationEnabled
 * -+ CloudTrailS3BucketNotPublic
 * -+ CloudTrailWithCloudWatchLogsIsEnabled
 * -+ CloudTrailLogsEncrypted
 * -+ ConfigIsEnabled
 * -+ S3BucketAccessLoggingIsEnabled
 * -+ CustomerManagedKeyRotationIsEnabled
 * -+ IamUnusedCredentialsAreDisabled
 * -+ IamCredentialRotation
 * -+ IamRequireLowercaseCharacters
 * -+ IamRequireUppercaseCharacters
 * -+ IamRequireSymbols
 * -+ IamRequireNumbers
 * -+ IamPasswordExpiryIsEnabled
 * -+ IamPasswordReusePrevention
 * -+ IamNoRootAccessKeys
 * -+ IamRootHardwareMfaIsEnabled
 * -+ IamUsersMfaIsEnabled
 * -+ IamPoliciesAttachedGroupsOnly
 * -+ SecurityGroupsGlobalPort22
 * -+ SecurityGroupsGlobalPort3389
 * -+ SecurityGroupsDefaultDisablesTraffic
 * -+ VpcFlowLoggingIsEnabled
 * **/

// Description: Checks that a CloudTrail exists that is set to multi-region
// Trigger Type: Periodic
// Scope of Changes: Global
// Required Parameter: None
function evaluateCloudTrailIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    var s3key = invokingEvent.s3ObjectKey;
    var s3bucket = invokingEvent.s3Bucket;
    readSnapshot(s3, s3key, s3bucket, function(err, snapshot) {
        if (err === null) {
            var compliance = 'NON_COMPLIANT';
            for (var i = 0; i < snapshot.configurationItems.length; i++) {
                var item = snapshot.configurationItems[i];
                if (item.resourceType === 'AWS::CloudTrail::Trail') {
                    if (item.configuration.isMultiRegionTrail) {
                        compliance = 'COMPLIANT';
                    }
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        } else {
            context.fail(err);
        }
    });
}

// Description: Checks that CloudTrail Log Validation is Enabled in All Regions.
// Trigger Type: Periodic
// Scope of Changes: Global
// Required Parameter: None
function evaluateCloudTrailLogFileValidationEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    var s3key = invokingEvent.s3ObjectKey;
    var s3bucket = invokingEvent.s3Bucket;
    readSnapshot(s3, s3key, s3bucket, function(err, snapshot) {
        if (err === null) {
            var compliance = 'NON_COMPLIANT';
            for (var i = 0; i < snapshot.configurationItems.length; i++) {
                var item = snapshot.configurationItems[i];
                if (item.resourceType === 'AWS::CloudTrail::Trail') {
                    if (item.configuration.isMultiRegionTrail && item.configuration.logFileValidationEnabled) {
                        compliance = 'COMPLIANT';
                    }
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        } else {
            context.fail(err);
        }
    });
}

// Description: Checks that the S3 Bucket used for CloudTrail logs is not public.
// Trigger Type: Periodic
// Scope of Changes: Global
// Required Parameter: None
function evaluateCloudTrailS3BucketNotPublic(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    var s3key = invokingEvent.s3ObjectKey;
    var s3bucket = invokingEvent.s3Bucket;
    readSnapshot(s3, s3key, s3bucket, function(err, snapshot) {
        var compliance = 'NOT_APPLICABLE';
        if (err === null) {
            for (var i = 0; i < snapshot.configurationItems.length; i++) {
                var item = snapshot.configurationItems[i];
                if (item.resourceType === 'AWS::CloudTrail::Trail') {
                    s3.getBucketAcl({ Bucket: item.configuration.s3BucketName }, function(err, data) {
                        if (!err) {
                            for (var i = 0; i < data.Grants.length; i++) {
                                if (data.Grants[i].Grantee.hasOwnProperty('Uri')) {
                                    if (compliance != 'NON_COMPLIANT' && data.Grants[i].Permission != 'READ' && !data.Grants[i].Grantee.uri.indexOf('AllUsers')) {
                                        compliance = 'COMPLIANT';
                                    } else {
                                        compliance = 'NON_COMPLIANT';
                                    }
                                } else {
                                    compliance = 'COMPLIANT';
                                }
                            }
                        }
                        putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
                    });
                }
            }
        } else {
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
            context.fail(err);
        }
    });
}

// Description: Checks that CloudTrail is integrated with CloudWatch Logs.
// Trigger Type: Periodic
// Scope of Changes: Global
// Required Parameter: None
function evaluateCloudTrailWithCloudWatchLogsIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    var s3key = invokingEvent.s3ObjectKey;
    var s3bucket = invokingEvent.s3Bucket;
    readSnapshot(s3, s3key, s3bucket, function(err, snapshot) {
        if (err === null) {
            var compliance = 'NON_COMPLIANT';
            for (var i = 0; i < snapshot.configurationItems.length; i++) {
                var item = snapshot.configurationItems[i];
                if (item.resourceType === 'AWS::CloudTrail::Trail') {
                    if (item.configuration.cloudWatchLogsLogGroupArn && item.configuration.cloudWatchLogsRoleArn) {
                        compliance = 'COMPLIANT';
                    }
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        } else {
            context.fail(err);
        }
    });
}

// Description: Checks that CloudTrail logs are encrypted.
// Trigger Type: Periodic
// Scope of Changes: Global
// Required Parameter: None
function evaluateCloudTrailLogsEncrypted(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    var s3key = invokingEvent.s3ObjectKey;
    var s3bucket = invokingEvent.s3Bucket;
    readSnapshot(s3, s3key, s3bucket, function(err, snapshot) {
        if (err === null) {
            var compliance = 'NON_COMPLIANT';
            for (var i = 0; i < snapshot.configurationItems.length; i++) {
                var item = snapshot.configurationItems[i];
                if (item.resourceType === 'AWS::CloudTrail::Trail') {
                    if (item.configuration.kmsKeyId) {
                        compliance = 'COMPLIANT';
                    }
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        } else {
            context.fail(err);
        }
    });
}

// Description: Checks that AWS Config is Enabled in All Regions.
// Trigger Type: Periodic
// Scope of Changes: Global
// Required Parameter: None
function evaluateConfigIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    config.describeConfigurationRecorders({}, function(err, data) {
        var compliance = 'NON_COMPLIANT';
        if (!err) {
            for (var i = 0; i < data.ConfigurationRecorders.length; i++) {
                if (data.ConfigurationRecorders[i].recordingGroup.allSupported && data.ConfigurationRecorders[i].recordingGroup.includeGlobalResourceTypes) {
                    compliance = 'COMPLIANT';
                }
            }
        }
        putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
    });
}

// Checks that all S3 buckets have access logging enabled.
// Trigger Type: Change Triggered
// Scope of Changes: AWS::S3::VPC
// Required Parameter: None
function evaluateS3BucketAccessLoggingIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    // Currently not supported.
    // http://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html
    putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
}

// Checks that all KMS keys have rotation enabled.
// Trigger Type: Change Triggered
// Scope of Changes: AWS::?
// Required Parameter: None
function evaluateCustomerManagedKeyRotationIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    // Currently not supported.
    // http://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html
    putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
}

// Checks that the unused access credentials have been disabled if unused for a
// set number of days.
// Trigger Type: Change Triggered
// Scope of Changes: IAM:User
// Required Parameter: MaximumUnusedAge
// Example Value: 30
function evaluateIamUnusedCredentialsAreDisabled(event,context,resourceType,resourceId,orderingTimestamp,ruleParameters){
    var invokingEvent = JSON.parse(event.invokingEvent);
    if (resourceType === 'AWS::IAM::User') {
        iam.listAccessKeys({ UserName: invokingEvent.configurationItem.resourceName }, function(err, keydata) {
            var compliance = 'NOT_APPLICABLE';
            if (!err) {
                if (keydata.AccessKeyMetadata.length > 0) {
                    for (var k = 0; k < keydata.AccessKeyMetadata.length; k++) {
                        iam.getAccessKeyLastUsed({ AccessKeyId: keydata.AccessKeyMetadata[k].AccessKeyId }, function(err, data) {
                            if (!err) {
                                var now = Date.now();
                                if (Math.floor((now - Date.parse(data.AccessKeyLastUsed.LastUsedDate)) / 86400000) > ruleParameters.MaximumUnusedAge) {
                                    compliance = 'NON_COMPLIANT';
                                } else {
                                    compliance = 'COMPLIANT';
                                }
                            }
                            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
                        });
                    }
                }
            }
        });
    } else {
        putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
    }
}

// Checks that the IAM User's Access Keys have been rotated within the specified
// number of days.
// Trigger Type: Change Triggered
// Scope of Changes: IAM:User
// Required Parameter: MaximumAccessKeyAge
// Example Value: 90
function evaluateIamCredentialRotation(event,context,resourceType,resourceId,orderingTimestamp,ruleParameters){
    var invokingEvent = JSON.parse(event.invokingEvent);
    if (resourceType === 'AWS::IAM::User') {
        iam.listAccessKeys({ UserName: invokingEvent.configurationItem.resourceName }, function(err, keydata) {
            var compliance = 'NOT_APPLICABLE';
            if (!err) {
                if (keydata.AccessKeyMetadata.length > 0) {
                    for (var k = 0; k < keydata.AccessKeyMetadata.length; k++) {
                        var now = Date.now();
                        if (Math.floor((now - Date.parse(keydata.AccessKeyMetadata[k].CreateDate)) / 86400000) > ruleParameters.MaximumAccessKeyAge) {
                            compliance = 'NON_COMPLIANT';
                        } else {
                            compliance = 'COMPLIANT';
                        }
                    }
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        });
    } else {
        putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
    }
}

// Checks that the IAM password policy requires a lowercase character.
function evaluateIamRequireLowercaseCharacters(event,context,resourceType,resourceId,orderingTimestamp){
    iam.getAccountPasswordPolicy(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.PasswordPolicy.RequireLowercaseCharacters) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}

// Checks that the IAM password policy requires a uppercase character.
function evaluateIamRequireUppercaseCharacters(event,context,resourceType,resourceId,orderingTimestamp){
    iam.getAccountPasswordPolicy(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.PasswordPolicy.RequireUppercaseCharacters) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}

// Checks that the IAM password policy requires a symbol.
function evaluateIamRequireSymbols(event,context,resourceType,resourceId,orderingTimestamp){
    iam.getAccountPasswordPolicy(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.PasswordPolicy.RequireSymbols) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}

// Checks that the IAM password policy requires a number.
function evaluateIamRequireNumbers(event,context,resourceType,resourceId,orderingTimestamp){
    iam.getAccountPasswordPolicy(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.PasswordPolicy.RequireNumbers) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}

// Checks that the IAM password policy expires passwords older than the
// configured maximum age.
function evaluateIamPasswordExpiryIsEnabled(event,context,resourceType,resourceId,orderingTimestamp,ruleParameters){
    iam.getAccountPasswordPolicy(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.PasswordPolicy.ExpirePasswords && iamdata.PasswordPolicy.MaxPasswordAge >= ruleParameters.MaximumPasswordAge) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}

// Checks that the IAM password policy prevents password reuse.
function evaluateIamPasswordReusePrevention(event,context,resourceType,resourceId,orderingTimestamp,ruleParameters){
    iam.getAccountPasswordPolicy(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.PasswordPolicy.PasswordReusePrevention >= ruleParameters.PasswordReusePrevention) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}

// Checks that the Root Account's Access Keys have been disabled.
function evaluateIamNoRootAccessKeys(event,context,resourceType,resourceId,orderingTimestamp){
    iam.getAccountSummary(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.SummaryMap['AccountAccessKeysPresent'] == 0) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}

// Checks that the Root Account has MFA Enabled.
function evaluateIamRootHardwareMfaIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    iam.getAccountSummary(function(err, iamdata) {
        if (!err) {
            var compliance = 'NON_COMPLIANT';
            if (iamdata.SummaryMap['AccountMFAEnabled'] == 1) {
                compliance = 'COMPLIANT';
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        }
    });
}
// Description: Checks that all IAM Users have MFA Enabled
// Trigger Type: Change Triggered
// Scope of Changes: IAM:User
// Required Parameter: None
function evaluateIamUsersMfaIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    if (resourceType == 'AWS::IAM::User') {
        iam.listMFADevices({ UserName: invokingEvent.configurationItem.resourceName }, function(mfaerr, mfadata) {
            var compliance = 'NON_COMPLIANT';
            if (!mfaerr) {
                if (mfadata.MFADevices.length > 0) {
                    compliance = 'COMPLIANT';
                }
            } else {
                console.log(mfaerr);
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        });
    } else {
        putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
    }
}

// Description: Checks that all IAM Users do not have policies attached to them.
// Trigger Type: Change Triggered
// Scope of Changes: IAM:User
// Required Parameter: None
function evaluateIamPoliciesAttachedGroupsOnly(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    if (resourceType == 'AWS::IAM::User') {
        var compliance = 'NON_COMPLIANT';
        if (invokingEvent.configurationItem.configuration.userPolicyList.length == 0 && invokingEvent.configurationItem.configuration.attachedManagedPolicies == 0) {
            compliance = 'COMPLIANT';
        }
        putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
    } else {
        putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
    }
}

// Checks that all security groups adhere to rules per passed parameters.
// Trigger Type: Change Triggered
// Scope of Changes: AWS::EC2::SecurityGroup
// Required Parameter: IpProtocol, FromPort, ToPort, CidrIp
function evaluateSecurityGroups(event,context,resourceType,resourceId,orderingTimestamp,ruleParameters){
    var invokingEvent = JSON.parse(event.invokingEvent);
    if (resourceType == 'AWS::EC2::SecurityGroup') {
        ec2.describeSecurityGroups({ GroupIds: [ resourceId ] }, function(err, data) {
            var compliance = 'NOT_APPLICABLE';
            if (!err) {
                if (data.SecurityGroups.length > 0) {
                    for (var i = 0; i < data.SecurityGroups.length; i++) {
                        if (data.SecurityGroups[i].IpPermissions.length > 0){
                            for (var r = 0; r < data.SecurityGroups[i].IpPermissions.length; r++){
                                for (var c = 0; c < data.SecurityGroups[i].IpPermissions[r].IpRanges.length; c++){
                                    if (
                                        compliance != 'NON_COMPLIANT'
                                        && data.SecurityGroups[i].IpPermissions[r].IpProtocol != ruleParameters.IpProtocol
                                        && data.SecurityGroups[i].IpPermissions[r].FromPort != ruleParameters.FromPort
                                        && data.SecurityGroups[i].IpPermissions[r].ToPort != ruleParameters.ToPort
                                        && data.SecurityGroups[i].IpPermissions[r].IpRanges[c].CidrIp != ruleParameters.CidrIp
                                    ) {
                                        compliance = 'COMPLIANT';
                                    } else {
                                        compliance = 'NON_COMPLIANT';
                                    }
                                }
                            }
                        } else {
                            compliance = 'COMPLIANT';
                        }
                    }
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        });
    } else {
        putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
    }
}

// Checks that all default security groups have no rules.
// Trigger Type: Change Triggered
// Scope of Changes: AWS::EC2::SecurityGroup
// Required Parameter: IpProtocol, FromPort, ToPort, CidrIp
function evaluateSecurityGroupsDefaultDisablesTraffic(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    if (resourceType == 'AWS::EC2::SecurityGroup') {
        ec2.describeSecurityGroups({ GroupIds: [ resourceId ] }, function(err, data) {
            var compliance = 'NOT_APPLICABLE';
            if (!err) {
                if (data.SecurityGroups.length > 0) {
                    for (var i = 0; i < data.SecurityGroups.length; i++) {
                        if (data.SecurityGroups[i].GroupName == 'default'){
                            if(data.SecurityGroups[i].IpPermissionsEgress.length != 0 && data.SecurityGroups[i].IpPermissions.length != 0){
                                compliance = 'NON_COMPLIANT';
                            } else {
                                compliance = 'COMPLIANT';
                            }
                        } else {
                            compliance = 'COMPLIANT';
                        }
                    }
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        });
    } else {
        putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
    }
}

// Checks that all Vpc networks have flow logging enabled.
// Trigger Type: Change Triggered
// Scope of Changes: AWS::EC2::VPC
// Required Parameter: None
function evaluateVpcFlowLoggingIsEnabled(event,context,resourceType,resourceId,orderingTimestamp){
    var invokingEvent = JSON.parse(event.invokingEvent);
    if (resourceType == 'AWS::EC2::VPC') {
        ec2.describeFlowLogs({ Filter: [{ Name: 'resource-id', Values: [ resourceId ] }] }, function(err, data) {
            var compliance = 'NON_COMPLIANT';
            if (!err) {
                if (data.FlowLogStatus == 'ACTIVE') {
                    compliance = 'COMPLIANT';
                }
            }
            putEvaluation(event,context,resourceType,resourceId,compliance,orderingTimestamp);
        });
    } else {
        putEvaluation(event,context,resourceType,resourceId,'NOT_APPLICABLE',orderingTimestamp);
    }
}
