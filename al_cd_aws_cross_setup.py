# Wrapper for AWS Cross Account Deployment in Alert Logic (Threat Manager)
# Author: welly.siauw@alertlogic.com
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
#
# Sample usage:
# Get the help menu:
#	python al_cd_aws_cross_setup.py --help
#
# Deploy and create new Threat Manager cross account link with name "TestEnv" with data center residency "Ashburn":
#	python al_cd_aws_cross_setup.py --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --aws 052672429986 --arn arn:aws:iam::052672429986:role/AlertLogicCrossAccountCI --ext My_ext_id --cred TestArgCred --env TestEnv --dc defender-us-ashburn
#
# Destroy the Threat Manager cross account link with environment ID specificed:
#   python test_create_delete.py DEL --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --envid 833CE538-04B4-441F-8318-DBFCB9C9B39C

from __future__ import print_function
import json, requests, datetime, sys, argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#API Endpoint
YARP_URL="api.cloudinsight.alertlogic.com"
ALERT_LOGIC_CI_SOURCE = "https://api.cloudinsight.alertlogic.com/sources/v1/"

def authenticate(user, paswd, yarp):
	#Authenticate with CI yarp to get token
	url = yarp
	user = user
	password = paswd
	r = requests.post('https://{0}/aims/v1/authenticate'.format(url), auth=(user, password), verify=False)
	if r.status_code != 200:
		sys.exit("Unable to authenticate %s" % (r.status_code))
	account_id = json.loads(r.text)['authentication']['user']['account_id']
	token = r.json()['authentication']['token']
	return token

def prep_credentials(iam_arn, iam_ext_id, cred_name):
	#Setup dictionary for credentials payload
	RESULT = {}
	RESULT['credential']  = {}
	RESULT['credential']['name'] = str(cred_name)
	RESULT['credential']['type'] = "iam_role"
	RESULT['credential']['iam_role'] = {}	
	RESULT['credential']['iam_role']['arn'] = str(iam_arn)
	RESULT['credential']['iam_role']['external_id'] = str(iam_ext_id)	
	return RESULT

def post_credentials(token, payload, target_cid):
	#Call API with method POST to create new credentials, return the credential ID
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/credentials/"
	REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False, data=payload)	
	print ("Create Credentials Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['credential']  = {}
		RESULT['credential']['id'] = "n/a"		
	return RESULT
	
def prep_source_environment(aws_account, cred_id, environment_name, defender_location):
	#Setup dictionary for environment payload
	RESULT = {}
	RESULT['source']  = {}
	RESULT['source']['config'] = {}
	RESULT['source']['config']['aws'] = {}
	RESULT['source']['config']['aws']['account_id'] = aws_account
	RESULT['source']['config']['aws']['defender_location_id'] = defender_location
	RESULT['source']['config']['aws']['defender_support'] = True
	RESULT['source']['config']['aws']['discover'] = True
	RESULT['source']['config']['aws']['scan'] = False
	RESULT['source']['config']['aws']['credential'] = {}
	RESULT['source']['config']['aws']['credential']['id'] = cred_id
	RESULT['source']['config']['collection_method'] = "api"
	RESULT['source']['config']['collection_type'] = "aws"
	RESULT['source']['enabled'] = True
	RESULT['source']['name'] = environment_name
	RESULT['source']['product_type'] = "outcomes"
	RESULT['source']['tags'] = []
	RESULT['source']['type'] = "environment"
	return RESULT	

def post_source_environment(token, payload, target_cid):
	#Call API with method POST to create new environment
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/"
	REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False, data=payload)	
	print ("Create Environment Status : " + str(REQUEST.status_code), str(REQUEST.reason))	
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['source'] = {}
		RESULT['source']['id'] = "n/a"
	return RESULT

def del_source_environment(token, target_env, target_cid):
	#Delete the specified environment by environment ID and CID
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/" + target_env	
	REQUEST = requests.delete(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)		
	print ("Delete Environment Status : " + str(REQUEST.status_code), str(REQUEST.reason))

def del_source_credentials(token, target_cred, target_cid):
	#Delete the specified credentials by credentials ID and CID
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/credentials/" + target_cred	
	REQUEST = requests.delete(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)		
	print ("Delete Credentials Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	
def get_source_environment(token, target_env, target_cid):
	#Get the source environment detail
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/" + target_env
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)	
	
	print ("Retrieving Environment info status : " + str(REQUEST.status_code), str(REQUEST.reason))	
	if REQUEST.status_code == 200:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['source'] = {}
		RESULT['source']['id'] = "n/a"
	return RESULT

def failback(token, cred_id, target_cid):
	#Failback, delete credentials if create environment failed
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/credentials/" + cred_id
	REQUEST = requests.delete(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)	
	print ("Delete Credentials Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	print ("Failback completed")

#MAIN MODULE
if __name__ == '__main__':

	parent_parser = argparse.ArgumentParser()
	subparsers = parent_parser.add_subparsers(help="Select mode", dest="mode")
	#Add parser for both ADD and DELETE mode
	add_parser = subparsers.add_parser("ADD", help="Create new environment")
	del_parser = subparsers.add_parser("DEL", help="Delete environment")
	
	#Parser argumetn for ADD
	add_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	add_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	add_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for this deployment")
	add_parser.add_argument("--aws", required=True, help="Customer AWS Account Number where IAM role is deployed")
	add_parser.add_argument("--arn", required=True, help="Cross Account IAM role arn")
	add_parser.add_argument("--ext", required=True, help="External ID specified in IAM role trust relationship")
	add_parser.add_argument("--cred", required=True, help="Credential name, free form label, not visible in Alert Logic UI")
	add_parser.add_argument("--env", required=True, help="Environment name, will be displayed in Alert Logic UI under Deployment")
	add_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")

	#Parser argumetn for DEL
	del_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	del_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	del_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID where the environment belongs")
	del_parser.add_argument("--envid", required=True, help="Environment ID that you wish to remove")	

	args = parent_parser.parse_args()

	#Set argument to variables
	if args.mode == "ADD":
				
		EMAIL_ADDRESS = args.user 
		PASSWORD = args.pswd 
		TARGET_CID = args.cid
		TARGET_AWS_ACCOUNT = args.aws
		TARGET_IAM_ROLE_ARN = args.arn
		TARGET_EXT_ID = args.ext
		TARGET_CRED_NAME = args.cred
		TARGET_ENV_NAME = args.env
		TARGET_DEFENDER = args.dc
			
	elif args.mode == "DEL":		
			
		EMAIL_ADDRESS = args.user 
		PASSWORD = args.pswd 
		TARGET_CID = args.cid
		TARGET_ENV_ID = args.envid
		
	
	if args.mode == "ADD":
		#Authenticate with Cloud Insight and retrieve token	
		TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))
		print ("Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = ADD \n")	
		
		#Create credentials using the IAM role ARN and external ID	
		CRED_PAYLOAD = prep_credentials(TARGET_IAM_ROLE_ARN, TARGET_EXT_ID, TARGET_CRED_NAME)
		CRED_RESULT = post_credentials(TOKEN, str(json.dumps(CRED_PAYLOAD, indent=4)), TARGET_CID)
		CRED_ID = str(CRED_RESULT['credential']['id'])

		if CRED_ID != "n/a":		
			print ("Cred ID : " + CRED_ID)
			#Create new environment using credentials ID and target AWS Account number
			ENV_PAYLOAD = prep_source_environment(TARGET_AWS_ACCOUNT, CRED_ID, TARGET_ENV_NAME, TARGET_DEFENDER)
			ENV_RESULT = post_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID)
			ENV_ID = str(ENV_RESULT['source']['id'])

			if ENV_ID != "n/a":
				print ("Env ID : " + ENV_ID)
				print ("\nCloud Defender Cross Account Role created successfully")
			else:
				print ("Failed to create environment source, see response code + reason above, starting fallback ..")
				failback(TOKEN, CRED_ID, TARGET_CID)

		else:			
			print ("Failed to create credentials, see response code + reason above, stopping ..")
		
	elif args.mode == "DEL":
		#Authenticate with Cloud Insight and retrieve token	
		TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))
		print ("Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = DEL \n")	

		#Check if the provided Environment ID exist and valid
		SOURCE_RESULT = get_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)
		
		if SOURCE_RESULT["source"]["id"] != "n/a":
			TARGET_CRED_ID = SOURCE_RESULT["source"]["config"]["aws"]["credential"]["id"]
			print ("Env ID : " + TARGET_ENV_ID)
			print ("Credential ID : " + TARGET_CRED_ID)

			#Delete the environment and credentials associated with that environment
			del_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)
			del_source_credentials(TOKEN, TARGET_CRED_ID, TARGET_CID)

		else:
			print ("Failed to find the environment ID, see response code + reason above, stopping ..")