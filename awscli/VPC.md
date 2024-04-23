#### HW-2 (Lesson 5)

#### 1.	Creating VPC with CIDR block 192.168.0.0/22:
```
aws ec2 create-vpc --cidr-block 192.168.0.0/22 --query Vpc.VpcId --output text
```
<details>
<summary>Output</summary>
vpc-0f63694cfe8d70553
</details>

```
export VPC_ID=vpc-0f63694cfe8d70553
```

__Adding tags to VPC:__
```
aws ec2 create-tags --resources $VPC_ID --tags Key=Name,Value=demo-vpc
```
```
aws ec2 create-tags --resources $VPC_ID --tags Key=Project,Value=demo
```

#### 2.	Creating public and private subnets:
__Creating  public subnet with CIDR block 192.168.1.0/24:__
```
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 192.168.1.0/24 --query 'Subnet.SubnetId' --output text
```
<details>
<summary>Output</summary>
subnet-00b2912416399cd53
</details>

```
export PUB_SUB_ID=subnet-00b2912416399cd53
```

__Adding tags to public subnet:__
```
aws ec2 create-tags --resources $PUB_SUB_ID --tags Key=Name,Value=public-sub
```
```
aws ec2 create-tags --resources $PUB_SUB_ID --tags Key=Project,Value=demo
```

__Creating private subnet with CIDR block 192.168.2.0/24:__
```
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 192.168.2.0/24 --query 'Subnet.SubnetId' --output text
```
<details>
<summary>Output</summary>
subnet-02dfa277c65f4f61c
</details>

```
export PRIV_SUB_ID=subnet-02dfa277c65f4f61c
```

__Adding tags to private subnet:__
```
aws ec2 create-tags --resources $PRIV_SUB_ID --tags Key=Name,Value=private-sub
```
```
aws ec2 create-tags --resources $PRIV_SUB_ID --tags Key=Project,Value=demo
```

__Editing settings for public subnet in web-console:__
Actions - Edit subnet settings
Switch ON "Enable auto-assign public IPv4 address" - Save


#### 3. Creating Internet gateway.
```
aws ec2 create-internet-gateway --query InternetGateway.InternetGatewayId --output text
```
<details>
<summary>Output</summary>
igw-09575c317b87613b6
</details>

```
export IGW_ID=igw-09575c317b87613b6
```

__Adding tags to internet gateway:__
```
aws ec2 create-tags --resources $IGW_ID --tags Key=Name,Value=demо-igw
```
```
aws ec2 create-tags --resources $IGW_ID --tags Key=Project,Value=demo
```

__Using the ID from the previous step, attach the internet gateway to our VPC:__
```
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
```


#### 4. Adding a route for public Internet access to the existing Route table:
```
aws ec2 create-route --route-table-id rtb-0e7deb0e58285f772 --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
```

#### 5. Creating a routing table for a private network:
```
aws ec2 create-route-table --vpc-id $VPC_ID --query RouteTable.RouteTableId --output text
```
<details>
<summary>Output</summary>
rtb-0d566b04271e53ba6
</details>

```
export PRIV_RT_ID=rtb-0d566b04271e53ba6
```

__Adding tags to the routing table:__
```
aws ec2 create-tags --resources $PRIV_RT_ID --tags Key=Name,Value=private-rt
```
```
aws ec2 create-tags --resources $PRIV_RT_ID --tags Key=Project,Value=demo
```

__Associate the routing table of the private network with the private subnet:__
```
aws ec2 associate-route-table --subnet-id $PRIV_SUB_ID --route-table-id $PRIV_RT_ID
```


#### 5. Getting the AMI ID image
```
aws ssm get-parameters --name "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id" --output table
```
<details>
<summary>Output</summary>
ami-026c3177c9bd54288
</details>

```
export AMI_ID=ami-026c3177c9bd54288
```

#### 6.	Creating security groups:
__Creating security group for  public subnet:__
```
aws ec2 create-security-group \
    --group-name demo-web-sg \
    --description "AWS ec2 CLI Demo web SG" \
    --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=demo-web-sg}, {Key=Project,Value=demo} ]' \
    --vpc-id "$VPC_ID"
```

<details>
<summary>Output</summary>
sg-01dc61765178b4e98
</details>

```
export SG_WEB_ID=sg-01dc61765178b4e98
```

__Adding group security rules (SSH permission):__
```
aws ec2 authorize-security-group-ingress \
    --group-id "$SG_WEB_ID" \
    --protocol tcp \
    --port 22 \
    --cidr "0.0.0.0/0"
```

__Creating security group for private subnet:__
```
aws ec2 create-security-group \
    --group-name demo-db-sg \
    --description "AWS ec2 CLI Demo db SC" \
    --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=demo-db-sg}, {Key=Project,Value=demo} ]' \
    --vpc-id "$VPC_ID"
```

<details>
<summary>Output</summary>
sg-0747537bb235740ea
</details>

```
export SG_DB_ID=sg-0747537bb235740ea
```

__Adding group security rules:__
```
aws ec2 authorize-security-group-ingress \
    --group-id "$SG_DB_ID" \
    --protocol -1 \
    --port -1 \
    --source-group $SG_DB_ID
```


#### 7. Creating Keys
```
aws ec2 create-key-pair --key-name web-key --key-type ed25519 --query "KeyMaterial" --output text > web-key.pem
```

__Editing permissions__
```
chmod 600 web-key.pem
```

__Adding to ssh agent__
```
sh-add ~/.ssh/web-key.pem
```


### 8. Creating EC2 (VM)
__Creating EC2 for WEB__
```
aws ec2 run-instances \
    --image-id $AMI_ID\
    --count 1 \
    --instance-type t2.micro \
    --key-name web-key \
    --security-group-ids $SG_WEB_ID $SG_DB_ID\
    --subnet-id $PUB_SUB_ID \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=demo-web-server}, {Key=Project,Value=demo}]' \
```

<details>
<summary>Output</summary>
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-026c3177c9bd54288",
            "InstanceId": "i-0324decfc754c7ae0",
            "InstanceType": "t2.micro",
            "KeyName": "web-key",
            "LaunchTime": "2024-04-22T12:32:20.000Z",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "eu-central-1c",
                "GroupName": "",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-192-168-1-246.eu-central-1.compute.internal",
            "PrivateIpAddress": "192.168.1.246",
            "ProductCodes": [],
            "PublicDnsName": "",
            "State": {
                "Code": 0,
                "Name": "pending"
            },
            "StateTransitionReason": "",
            "SubnetId": "subnet-00b2912416399cd53",
            "VpcId": "vpc-0f63694cfe8d70553",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [],
            "ClientToken": "b0485db7-f856-46fe-beb6-ffb8b9c4f6ca",
            "EbsOptimized": false,
            "EnaSupport": true,
            "Hypervisor": "xen",
            "NetworkInterfaces": [
                {
                    "Attachment": {
                        "AttachTime": "2024-04-22T12:32:20.000Z",
                        "AttachmentId": "eni-attach-0b53b0e6153bd0bf5",
                        "DeleteOnTermination": true,
                        "DeviceIndex": 0,
                        "Status": "attaching",
                        "NetworkCardIndex": 0
                    },
                    "Description": "",
                    "Groups": [
                        {
                            "GroupName": "demo-web-sg",
                            "GroupId": "sg-01dc61765178b4e98"
                        },
                        {
                            "GroupName": "demo-db-sg",
                            "GroupId": "sg-0747537bb235740ea"
                        }
                    ],
                    "Ipv6Addresses": [],
                    "MacAddress": "0a:22:a1:d3:be:f5",
                    "NetworkInterfaceId": "eni-057db6af9912af99c",
                    "OwnerId": "775696009145",
                    "PrivateIpAddress": "192.168.1.246",
                    "PrivateIpAddresses": [
                        {
                            "Primary": true,
                            "PrivateIpAddress": "192.168.1.246"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Status": "in-use",
                    "SubnetId": "subnet-00b2912416399cd53",
                    "VpcId": "vpc-0f63694cfe8d70553",
                    "InterfaceType": "interface"
                }
            ],
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
                {
                    "GroupName": "demo-web-sg",
                    "GroupId": "sg-01dc61765178b4e98"
                },
                {
                    "GroupName": "demo-db-sg",
                    "GroupId": "sg-0747537bb235740ea"
                }
            ],
            "SourceDestCheck": true,
            "StateReason": {
                "Code": "pending",
                "Message": "pending"
            },
            "Tags": [
                {
                    "Key": "Project",
                    "Value": "demo"
                },
                {
                    "Key": "Name",
                    "Value": "web-server"
                }
            ],
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 1
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "pending",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 1,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "InstanceMetadataTags": "disabled"
            },
            "EnclaveOptions": {
                "Enabled": false
            },
            "BootMode": "uefi-preferred",
            "PrivateDnsNameOptions": {
                "HostnameType": "ip-name",
                "EnableResourceNameDnsARecord": false,
                "EnableResourceNameDnsAAAARecord": false
            }
        }
    ],
    "OwnerId": "775696009145",
    "ReservationId": "r-0e0f76a619bdce706"
}

</details>

__Creating EC2 for DB__
```
aws ec2 run-instances \
    --image-id $AMI_ID\
    --count 1 \
    --instance-type t2.micro \
    --key-name web-key \
    --security-group-ids $SG_DB_ID\
    --subnet-id $PRIV_SUB_ID \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=demo-db-server}, {Key=Project,Value=demo}]' \
```

<details>
<summary>Output</summary>
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-026c3177c9bd54288",
            "InstanceId": "i-0f59fdbac07b6b81a",
            "InstanceType": "t2.micro",
            "KeyName": "web-key",
            "LaunchTime": "2024-04-22T12:35:56.000Z",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "eu-central-1c",
                "GroupName": "",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-192-168-2-76.eu-central-1.compute.internal",
            "PrivateIpAddress": "192.168.2.76",
            "ProductCodes": [],
            "PublicDnsName": "",
            "State": {
                "Code": 0,
                "Name": "pending"
            },
            "StateTransitionReason": "",
            "SubnetId": "subnet-02dfa277c65f4f61c",
            "VpcId": "vpc-0f63694cfe8d70553",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [],
            "ClientToken": "0940ca0d-600f-4017-b207-6a5d20b999b0",
            "EbsOptimized": false,
            "EnaSupport": true,
            "Hypervisor": "xen",
            "NetworkInterfaces": [
                {
                    "Attachment": {
                        "AttachTime": "2024-04-22T12:35:56.000Z",
                        "AttachmentId": "eni-attach-0abc95d886645d48a",
                        "DeleteOnTermination": true,
                        "DeviceIndex": 0,
                        "Status": "attaching",
                        "NetworkCardIndex": 0
                    },
                    "Description": "",
                    "Groups": [
                        {
                            "GroupName": "demo-db-sg",
                            "GroupId": "sg-0747537bb235740ea"
                        }
                    ],
                    "Ipv6Addresses": [],
                    "MacAddress": "0a:df:71:c6:e9:f1",
                    "NetworkInterfaceId": "eni-0c74c7f612527d3ae",
                    "OwnerId": "775696009145",
                    "PrivateIpAddress": "192.168.2.76",
                    "PrivateIpAddresses": [
                        {
                            "Primary": true,
                            "PrivateIpAddress": "192.168.2.76"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Status": "in-use",
                    "SubnetId": "subnet-02dfa277c65f4f61c",
                    "VpcId": "vpc-0f63694cfe8d70553",
                    "InterfaceType": "interface"
                }
            ],
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
                {
                    "GroupName": "demo-db-sg",
                    "GroupId": "sg-0747537bb235740ea"
                }
            ],
            "SourceDestCheck": true,
            "StateReason": {
                "Code": "pending",
                "Message": "pending"
            },
            "Tags": [
                {
                    "Key": "Project",
                    "Value": "demo"
                },
                {
                    "Key": "Name",
                    "Value": "demo-db-server"
                }
            ],
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 1
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "pending",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 1,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "InstanceMetadataTags": "disabled"
            },
            "EnclaveOptions": {
                "Enabled": false
            },
            "BootMode": "uefi-preferred",
            "PrivateDnsNameOptions": {
                "HostnameType": "ip-name",
                "EnableResourceNameDnsARecord": false,
                "EnableResourceNameDnsAAAARecord": false
            }
        }
    ],
    "OwnerId": "775696009145",
    "ReservationId": "r-0c306bfe76c87fd68"
}

</details>


#### 8. Connection via SSH (WEB)+ Jump Host (DB):
__Get public (web console or command in Linux)__
```
aws ec2 describe-instances | grep Public
```
<details>
<summary>Output</summary>
"PublicDnsName": "",
                    "PublicDnsName": "",
                    "PublicIpAddress": "3.67.204.216",
                                "PublicDnsName": "",
                                "PublicIp": "3.67.204.216"
                                        "PublicDnsName": "",
                                        "PublicIp": "3.67.204.216"
                    "PublicDnsName": "",
</details>



__"PublicIp": "3.67.204.216"__

__Connecting to WEB VM server via SSH__
```
ssh ubuntu@3.67.204.216
```
ubuntu@ip-192-168-1-246:~$

__Ping from WEB to DB__
buntu@ip-192-168-1-246:~$ ping  192.168.2.76
PING 192.168.2.76 (192.168.2.76) 56(84) bytes of data.
64 bytes from 192.168.2.76: icmp_seq=1 ttl=64 time=0.880 ms
64 bytes from 192.168.2.76: icmp_seq=2 ttl=64 time=0.515 ms


__Connecting to the DB server via SSH via jump-host (WEB server)__
```
ssh -J ubuntu@3.67.204.216 ubuntu@192.168.2.76
```
ubuntu@ip-192-168-2-76:~$
