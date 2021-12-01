import json
import boto3
import datetime
#from datetime import datetime , date
#from datetime import date
import os
import requests


client = boto3.client('ec2')
all_regions=client.describe_regions()
list_of_Regions = []
for each_reg in all_regions['Regions']:
    list_of_Regions.append(each_reg['RegionName'])


ct_client = boto3.client('cloudtrail')

# Get the current AWS Account ID
sts = boto3.client("sts")
account_id = sts.get_caller_identity()["Account"]
 

def lambda_handler(event, context):
    client_id = os.environ['CLIENT_ID']
    client_secret =os. environ['CLIENT_SECRET']
    username = os.environ['USERNAME']
    password = os.environ['PASSWORD']
    #oAuth Response
    url = "https://servicecafedev.service-now.com/oauth_token.do"
    payload="grant_type=password&client_id=" + client_id + "&client_secret=" + client_secret + "&username=" + username + "&password=" + password
	
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': 'BIGipServerpool_servicecafedev=2541902346.40766.0000; JSESSIONID=C0FFB74F88A66ED5E90835E3CB0F8B4D; glide_user_route=glide.8145274ea778054324de3882d975bce4'
    }
    responseSNOW = requests.request("POST", url, headers=headers, data=payload)
    token = json.loads(responseSNOW.text)["access_token"]
    result = []
    
    for region in list_of_Regions:
        #print(region)
        eip = getElasticIPs(region)
        #print(eip)
        result = result + eip
    # result = eips("us-east-2")
    
    url = "https://servicecafedev.service-now.com/api/sn_cmp/resource_optimization" 

    headers1 = {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'

    }   
    data = {
        "elp_data": result
    }
    data = result
    print(data)
    # #print(json.dumps(data)) 
    responseSNOW = requests.request("POST", url, headers=headers1, data=json.dumps(data))
    print(responseSNOW)
 

    return {
        #'statuscode':200,
        #'body': result
        'body': json.loads(json.dumps(result, default=datetime_handler))
        # 'data': json.loads(json.dumps(event_res, default=datetime_handler))
    }

def getElasticIPs(region):
    print("Current region = ", region)
    outcome = []

    
    client = boto3.client('ec2',region_name=region)
    # ct_client = boto3.client('cloudtrail')
    
    filter = [
        {
            'Name': 'domain',
            'Values': ['vpc']
        }
    ]
    elastic_ip = client.describe_addresses(Filters=filter)
    
    present_day = datetime.date.today()
    print("present_day = ", present_day)
    
    
    for eip in elastic_ip['Addresses']:
        
        
        
        detach_time = datetime.datetime.now()
        
        detach_time = getIpAllocationTime(eip['AllocationId'], detach_time)
        
        eip_association_id = getIpAssociationId(eip['AllocationId'])
        
        if(eip_association_id):
            detach_time = getIpDisassociateTime(eip_association_id, detach_time)
        
        
        # print(ip)
        ip_name = ""
        if('Tags' in eip):
            for tag in eip['Tags']:
                if tag['Key'] == "Name":
                    ip_name = tag['Value']
                    break
        
        print("detach_time = ", detach_time)
        ideal_time = idle_days(detach_time.date(), present_day)
        
        #if ideal_time != 0 :
        if "InstanceId" and "NetworkInterfaceId" not in eip:
            outcome.append({
                'ip': eip['PublicIp'],
                'name': ip_name,
                'location': eip['NetworkBorderGroup'],
                'idle_days': ideal_time,
    			'provider' : "AWS",
    			'resource_type' : "AWS.NetWork/networkInterfaces",
    			'account' : account_id, 
    			
            })
        
    return outcome
  

def getIpAllocationTime(eipAllocationId, detach_time):
    
    event_res = ct_client.lookup_events(
           
        LookupAttributes = [
            {
                'AttributeKey':'ResourceName',
                'AttributeValue':eipAllocationId #Replace this value with EIP Allocation ID
            }
        ],
        MaxResults=5
    )
    
    for event in event_res['Events']:
        if (event['EventName'] == 'AllocateAddress'):
            detach_time = event['EventTime']             
            break
    
    return detach_time
    
def getIpAssociationId(eipAllocationId):
    event_res = ct_client.lookup_events(
        LookupAttributes = [
            {
                'AttributeKey':'ResourceName',
                'AttributeValue':eipAllocationId #Replace this value with EIP Allocation ID
            }
        ],
        MaxResults=5
    )
    
    eip_association_id = ""
    for event in event_res['Events']:
        if (event['EventName'] == 'AssociateAddress'):
            eip_association_id = event['Resources'][2]['ResourceName']             
            break
    
    return eip_association_id

def getIpDisassociateTime(eip_association_id, detach_time):
    event_res = ct_client.lookup_events(
        LookupAttributes = [
            {
                'AttributeKey':'ResourceName',
                'AttributeValue': eip_association_id #Replace this value with eip_association_id
            }
        ],
        MaxResults=1
    )
    
   
    for event in event_res['Events']:
        if (event['EventName'] == 'DisassociateAddress'):
            detach_time = event['EventTime']
            break
    
    return detach_time    

def idle_days(detachday, present_day):
    # print("detachday = ", detachday)
    # print("present_day = ", present_day)
    
    
    # print(type(present_day), type(detachday))
    day_diff = present_day - detachday
    #print("day_diff",day_diff)
    
    
    ideal_time = day_diff.days
   # print(ideal_time)
    return ideal_time


def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    raise TypeError("Unknown type")
    
