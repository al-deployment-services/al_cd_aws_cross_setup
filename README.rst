Wrapper for AWS Cross Account Deployment in Alert Logic (Threat Manager)
=================
This script will create the Threat Manager AWS Cross Account role link setup. Two components that will be created:

- New Credentials based on the provided IAM role + external ID 
- New Source based on the given credentials and AWS Account ID

Requirements
------------
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Insight (this call is made from Cloud Insight API end point)
* IAM role for Threat Manager (https://docs.alertlogic.com/gsg/amazon-web-services-cloud-defender-cross-account-role-config.htm)

Deployment Mode
---------------
* ADD = will create the Threat Manager AWS Cross Account Role link
* DEL = will delete the existing Threat Manager AWS Cross Account Role link

Sample ADD Usage
----------------

`python al_cd_aws_cross_setup.py ADD --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --aws 052672429986 --arn arn:aws:iam::052672429986:role/AlertLogicCrossAccountCD --ext My_ext_id --cred TestArgCred --env TestEnv --dc defender-us-ashburn`

Arguments
----------
  -h, --help   show this help message and exit
  --user USER  User name / email address for API Authentication
  --pswd PSWD  Password for API Authentication
  --cid CID    Alert Logic Customer CID as target for this deployment
  --aws AWS    Customer AWS Account Number where IAM role is deployed
  --arn ARN    Cross Account IAM role arn
  --ext EXT    External ID specified in IAM role trust relationship
  --cred CRED  Credential name, free form label, not visible in Alert Logic UI
  --env ENV    Environment name, will be displayed in Alert Logic UI under Deployment
  --dc DC      Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport

Take note of the output from the script, you will need to record the Environment ID if you wish to delete it later using this script (see below)

Sample DEL Usage
----------------

`python al_cd_aws_cross_setup.py DEL --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --envid 833CE538-04B4-441F-8318-DBFCB9C9B39C`

Arguments
----------
  -h, --help   show this help message and exit
  --user USER  User name / email address for API Authentication
  --pswd PSWD  Password for API Authentication
  --cid CID    Alert Logic Customer CID as target for this deployment
  --envid ENVUD    Environment ID that you wish to delete


License and Authors
===================
License:
Distributed under the Apache 2.0 license.

Authors: 
Welly Siauw (welly.siauw@alertlogic.com)
