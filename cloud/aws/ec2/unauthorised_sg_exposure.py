from netaddr import IPNetwork
from functools import lru_cache
from copy import deepcopy
from datetime import date, datetime
import re
import json
import jmespath
import boto3
import os
import argparse
import csv

def __json_serial(obj):
    if isinstance(obj, (date,datetime)):
        return obj.isoformat()

def get_sgs(session=None, region=None, security_group_id=None):
    def describe_sgs():
        client = session.client('ec2', region_name=region)
        paginator = client.get_paginator('describe_security_groups')
        
        marker = None
        sgs = []
        while True:

            response_iterator = paginator.paginate(PaginationConfig= \
                                                {'PageSize': 123,
                                                    'StartingToken': marker
                                                    })
                
            for page in response_iterator:
                sgs += page["SecurityGroups"]
            try:
                marker = page['Marker']
            except KeyError:
                break
        
        return sgs
    
    sgs = describe_sgs()
    if security_group_id:
        for sg in sgs:
            if sg["GroupId"] == security_group_id:
                return [sg]
        return []
    else:
        return sgs

@lru_cache(maxsize=1000)
def get_attached_enis(session=None, region=None, security_group_id=None):
    client = session.client('ec2', region_name=region)
    paginator = client.get_paginator('describe_network_interfaces')
    
    marker = None
    attached_enis = []
    while True:
        response_iterator = paginator.paginate(PaginationConfig= \
                                            {'PageSize': 123,
                                                'StartingToken': marker
                                                })
        for page in response_iterator:
            for eni in page["NetworkInterfaces"]:
                if eni.get("Groups"):
                # Nat gateway have empty Groups. Hence this check.
                # They dont have any attached security group
                    if security_group_id in [i["GroupId"] for i in eni["Groups"]]:
                        attached_enis.append(eni)
        try:
            marker = page['Marker']
        except KeyError:
            break
    return attached_enis

def is_attached_to_lb(eni=None):
    if jmespath.search("Association.IpOwnerId", eni) == "amazon-elb":
        return True
    elif jmespath.search("Attachment.InstanceOwnerId", eni) == "amazon-elb":
        return True
    elif jmespath.search("RequesterId", eni) == "amazon-elb":
        return True
    elif set(jmespath.search("PrivateIpAddresses[].Association.IpOwnerId", eni)) == {"amazon-elb"}:
        return True
    elif jmespath.search("InterfaceType", eni) == "network_load_balancer":
        return True
    
    return False


def get_attached_resource_info(eni=None, string=True):
    resource_attributes = { 
                           "Public DNS Name": "Association.PublicDnsName", 
                           "Public Ip": "Association.PublicIp",  
                           "Instance Id": "Attachment.InstanceId", 
                           "Owner Id": "Attachment.InstanceOwnerId", 
                           "Availability Zone": "AvailabilityZone", 
                           "Subnet Id": "SubnetId", 
                           "Vpc Id": "VpcId", 
                           "Tags": "TagSet[].join(':',['tag',Key,Value])", 
                           "Interface Type": "InterfaceType"
                           }
    resource_info = dict()
    for field in resource_attributes:
        attr = jmespath.search(resource_attributes[field], eni)
        if attr:
            resource_info[field] = attr
        else:
            resource_info[field] = "N/A"
    info= ""
    if string:
        for key in resource_info:
            info = info + f" {key} - "+str(resource_info[key])+", "
    info = info.rstrip(" ").rstrip(",")
    return info

def normalize_port(from_port=None, to_port=None, protocol=None):
    
    allowed_ports_range = range(0,0,1)
    normalized_protocol = None
    
    if protocol == "-1":
        normalized_protocol = "all"
        allowed_ports_range = range(0, 65536, 1)
    # 0 is considered as False and misses this check. Hence the None based condition.
    elif from_port is not None:
        if protocol == "icmp":
            # When protocol is icmp, FromPort signifies icmp type and ToPort signifies the icmp code for that type
            if from_port == -1:
                normalized_protocol = "icmp_type:all_icmp_code:all"
            else:
                if to_port == -1:
                    # if ToPort is -1, it means all codes of that icmp type is allowed
                    normalized_protocol = "icmp_type:{}_icmp_code:all".format(from_port)
                else:
                    normalized_protocol = "icmp_type:{}_icmp_code:{}".format(from_port, to_port)
        
        elif protocol == "icmpv6":
            # In icmpv6 , AWS does not allow one to include separate icmpv6 codes unlike icmpv4.
            # ALL ICMPv6 and CUSTOM ICMPv6 both behave similarly allowing all ICMP v6 types
            normalized_protocol = "icmpv6_type:all_icmpv6_code:all"
            
        else: 
            normalized_protocol = protocol
            allowed_ports_range = range(from_port, to_port + 1, 1)
            
    else:
        # This is met only if any protocol apart from icmp, icmpv6 , tcp , udp is specified as part of a permission.
        # Ref:https://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-ingress.html 
        # IpProtocol section. 
        
        # In case of custom protocol , all ports are allowed by default and 
        # the FromPort and ToPort is not returned as a key. This is implicitly inferred.
        # Refer the same link provided above.
        
        # In case of custom protocols , code is provided as part of security group permission
        # Refer http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml for the code vs protocol mapping
        normalized_protocol = "custom_code-{}".format(permission.get("IpProtocol"))
        allowed_ports_range = range(0, 65536, 1)
    
    return allowed_ports_range, normalized_protocol   

def enrich_world_exposed_attached_nonlb_resources(ip=None, session=None, region=None, security_group_id=None, exceptions=None):
    if ip.ip.format() in ["0.0.0.0", "::"]:
        for i in get_attached_enis(session=session, region=region, security_group_id=security_group_id):
            if is_attached_to_lb(eni=i):
                pass
            else:
                info = get_attached_resource_info(eni=i, string=True)
                ar = i["NetworkInterfaceId"] +  f" ({info})"
                message = "guardian:exposed_sg_attached_to_non-elbs"
                if not message in exceptions:
                    exceptions[message] = []
                if not ar in exceptions[message]:
                    exceptions[message].append(ar)
    return exceptions

def is_range_subset(subset_range, parent_range):
    if subset_range.start >= parent_range.start and subset_range.stop <= parent_range.stop:
        return True
    return False

def enrich_world_exposed_unauthorised_protocol_info(allowed_protocol=None, exceptions=None):
    if allowed_protocol in AUTHORISED_PUBLIC_EXPOSABLE_PROTOCOLS:
        pass
    else:
        if allowed_protocol == "icmp_type:3_icmp_code:4" :
            # Ref: https://github.com/kubernetes/cloud-provider-aws/issues/101
            # Ref: https://www.fir3net.com/Networking/Protocols/path-mtu-path-mtu-black-holes.html
            # This is required for kubernetes related discovery. Hence this is allowed.
            return exceptions
        
        # Unauthorised protocol exposed to the world
        message = "guardian:unauthorised_protocol_exposed_to_world"
        if not message in exceptions:
            exceptions[message] = []
        if not allowed_protocol in exceptions[message]:
            exceptions[message].append(allowed_protocol)
    return exceptions

def enrich_world_exposed_unauthorised_port_info(allowed_port_range=None, allowed_protocol=None, exceptions=None):
    if not "icmp" in allowed_protocol:
        # ICMP does not expose any port since it is not a service based protocol
        if any([is_range_subset(allowed_port_range, i) for i in AUTHORISED_PUBLIC_EXPOSABLE_PORT_RANGES]):
            pass
        else:
            # Unauthorised port exposed to the world
            message = "guardian:unauthorised_ports_exposed_to_world"
            if not message in exceptions:
                exceptions[message] = []
            port_range_string = port_ranges_2_string(port_range=allowed_port_range)
            if not port_range_string in exceptions[message]:
                exceptions[message].append(port_range_string)
    return exceptions

def enrich_unauthorised_ip_info(ip=None, exceptions=None):    
    if not(AUTHORISED_INGRESS_PUBLIC_IPS and any([ip in i for i in AUTHORISED_INGRESS_PUBLIC_IPS])):
        message = "guardian:unauthorised_exposure_to_public_ips"
        if not message in exceptions:
            exceptions[message] = []
        if not str(ip) in exceptions[message]:
            exceptions[message].append(str(ip))
    
    return exceptions

def enrich_unshared_prefix_lists(prefix_list_id=None, exceptions=None):
    message = "guardian:unshared_prefix_list_in_usage"
    if not message in exceptions:
        exceptions[message] = []
    if not prefix_list_id in exceptions[message]:
        exceptions[message].append(prefix_list_id)
    return exceptions
    
def review_permission(ips=None, unshared_prefix_list_ids=None, from_port=None, to_port=None, protocol=None, session=None, region=None, security_group_id=None, exceptions=None):
    
    port_range, protocol = normalize_port(from_port=from_port, to_port=to_port, protocol=protocol)
    if exceptions is None:
        exceptions = dict()
    
    if unshared_prefix_list_ids:
        for pl in unshared_prefix_list_ids:
            exceptions = enrich_unshared_prefix_lists(prefix_list_id=pl, exceptions=exceptions)
        # Since we are not aware of whether public IPs are of prefix list, we assume the worst and enric the protocol and port information
        exceptions = enrich_world_exposed_unauthorised_protocol_info(allowed_protocol=protocol, exceptions=exceptions)
        exceptions = enrich_world_exposed_unauthorised_port_info(allowed_port_range=port_range, exceptions=exceptions, allowed_protocol=protocol)
    else:
        for ip in ips:
            ip = IPNetwork(ip)
            # We are not bothered about private ip ranges
            if not ip.is_private():
                if ip.ip.format() in ["::", "0.0.0.0"]:
                    exceptions = enrich_world_exposed_attached_nonlb_resources(ip=ip, session=session ,region=region, security_group_id=security_group_id, exceptions=exceptions)
                    exceptions = enrich_world_exposed_unauthorised_protocol_info(allowed_protocol=protocol, exceptions=exceptions)
                    exceptions = enrich_world_exposed_unauthorised_port_info(allowed_port_range=port_range, exceptions=exceptions, allowed_protocol=protocol)
                else:
                    # In case permission is exposed to only specific Ips , we are not bothered about ports / protocols / type of resource exposed
                    # since in these cases, there would be a concious decision made to expose a specific port / protocol / resource.
                    # Hence as long as IP is authorised , it would be reasonable from risk standpoint.
                    exceptions = enrich_unauthorised_ip_info(ip=ip, exceptions=exceptions)
    
    return exceptions

def process_permission(permission=None, sg_id=None, session=None, region=None):
    exceptions = dict()
    from_port=permission.get("FromPort")
    to_port=permission.get("ToPort")
    protocol=permission.get("IpProtocol")
    
    if permission.get("IpRanges"):
        exceptions = review_permission(ips=[ip["CidrIp"] for ip in permission.get("IpRanges")], 
                                       from_port=from_port, to_port=to_port, protocol=protocol,
                                       session=session, region=region, security_group_id=sg_id, 
                                       exceptions=exceptions)
    if permission.get("Ipv6Ranges"):
        exceptions = review_permission(ips=[ip["CidrIpv6"] for ip in permission.get("Ipv6Ranges")], 
                                       from_port=from_port, to_port=to_port, protocol=protocol,
                                       session=session, region=region, security_group_id=sg_id, 
                                       exceptions=exceptions)
        
    if permission.get("PrefixListIds"):
        prefix_list_ids = [i["PrefixListId"] for i in permission["PrefixListIds"]]
        unshared_prefix_list_ids = set()
        client = session.client('ec2', region_name=region)
        paginator = client.get_paginator('get_managed_prefix_list_entries')
        entries = set()
        # Prefix list irrespective of owned by the current account / foreign account 
        # if shared can be read by the current account
        
        # In case sharing is stopped , the prefix list cannot be read resulting in below
        # API call to fail.
        # Ref: https://docs.aws.amazon.com/vpc/latest/userguide/sharing-managed-prefix-lists.html#sharing-unshare
        for pl in prefix_list_ids:
            try:
                marker = None
                while True:
                    response_iterator = paginator.paginate(PrefixListId=pl,
                                                        PaginationConfig= \
                                                        {'PageSize': 123,
                                                            'StartingToken': marker
                                                            })
                    for page in response_iterator:
                        for entry in page["Entries"]:
                            if entry:
                                entries.add(entry.get("Cidr"))
                    try:
                        marker = page['Marker']
                    except KeyError:
                        break
            except:
                unshared_prefix_list_ids.add(pl)
        
        entries = list(entries)
        unshared_prefix_list_ids = list(unshared_prefix_list_ids)
        
        if entries:
            exceptions = review_permission(ips=entries, 
                                        from_port=from_port, to_port=to_port, protocol=protocol,
                                        session=session, region=region, security_group_id=sg_id, 
                                        exceptions=exceptions)
        if unshared_prefix_list_ids:
            exceptions = review_permission(unshared_prefix_list_ids=unshared_prefix_list_ids, 
                                    from_port=from_port, to_port=to_port, protocol=protocol,
                                    session=session, region=region, security_group_id=sg_id, 
                                    exceptions=exceptions)
                         
        
        
    return exceptions

def list_to_ranges(list_values):
    # Link : https: // stackoverflow.com / a / 43531212
    ret = []
    for val in sorted(list_values):
        if not ret or ret[-1][-1]+1 != val:
            ret.append([val])
        else:
            ret[-1].append(val)
    return ",".join([str(x[0]) if len(x)==1 else str(x[0])+"-"+str(x[-1]+1) for x in ret])

def port_ranges_2_string(port_range=None):
    if port_range.start == port_range.stop -1:
        return str(port_range.start)
    else:
        return  str(port_range.start) + "-" +  str(port_range.stop-1)

def port_strings_2_ranges(authorised_ports = None):
    consolidated_authorised_ports = set()

    for port in authorised_ports:
        if type(port) == str:
            try:
                # Supports range 0-65535
                # Link : https://github.com/cusspvz/proxywrap/blob/9fb60d7f3132d556c5186598248ab2d9ff56303f/lib/proxy-protocol.regexp.js#L85
                if re.match("^([0-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])"
                            "\-([0-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])$",
                            port):
                    if int(port.split("-")[0]) > int(port.split("-")[1]):
                        raise ValueError("Invalid Range - {}".format(port))
                    consolidated_authorised_ports = consolidated_authorised_ports.union(
                        set([*range(int(port.split("-")[0]), int(port.split("-")[1]) + 1, 1)]))
                else:
                    # Supports port as string
                    consolidated_authorised_ports.add(int(port))
            except ValueError as e:
                raise ValueError("Invalid Range - {}".format(port))
        elif type(port) == int:
            # Supports port as int
            consolidated_authorised_ports.add(port)                    
    
    ranges = []
    range_strings = list_to_ranges(list(consolidated_authorised_ports))
    if range_strings:
        for r in range_strings.split(","):
            if "-" in r:
                ranges.append(range(int(r.split("-")[0]), int(r.split("-")[1])))
            else:
                ranges.append(range(int(r), int(r)+1))
    
    return ranges
     
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-r', '--region', required=True)
    parser.add_argument('-o', '--output-path', required=True, help="path of the outputfile")
    parser.add_argument('-f', '--output-format', required=True, help="format of the output", choices=["csv", "json"])
    parser.add_argument('-p', '--profile', help="profile for the current session")

    args = parser.parse_args()

    AWS_REGION = args.region
    OUTPUT_PATH = args.output_path
    AWS_PROFILE = args.profile
    FORMAT = args.output_format
    
    AUTHORISED_INGRESS_PUBLIC_IPS = os.environ.get("AUTHORISED_INGRESS_IPS") or ""
    AUTHORISED_PUBLIC_EXPOSABLE_PORT_RANGES = os.environ.get("AUTHORISED_EXPOSABLE_PORTS") or ""
    AUTHORISED_PUBLIC_EXPOSABLE_PROTOCOLS = os.environ.get("AUTHORISED_EXPOSABLE_PROTOCOLS") or ""
    EXCEPTION_SG_IDS = os.environ.get("UNAUTHORISED_SG_EXCEPTION_SG_IDS") or []
        
    if AUTHORISED_INGRESS_PUBLIC_IPS:
        AUTHORISED_INGRESS_PUBLIC_IPS = [IPNetwork(i) for i in AUTHORISED_INGRESS_PUBLIC_IPS.split(",")]
    else:
        AUTHORISED_INGRESS_PUBLIC_IPS = []
        
    if AUTHORISED_PUBLIC_EXPOSABLE_PORT_RANGES:
        AUTHORISED_PUBLIC_EXPOSABLE_PORT_RANGES = port_strings_2_ranges(authorised_ports=[p.strip() for p in AUTHORISED_PUBLIC_EXPOSABLE_PORT_RANGES.split(",")])
    else:
        AUTHORISED_PUBLIC_EXPOSABLE_PORT_RANGES = []
        
    if AUTHORISED_PUBLIC_EXPOSABLE_PROTOCOLS:
        AUTHORISED_PUBLIC_EXPOSABLE_PROTOCOLS = [p.strip() for p in AUTHORISED_PUBLIC_EXPOSABLE_PROTOCOLS.split(",")]
    else:
        AUTHORISED_PUBLIC_EXPOSABLE_PROTOCOLS = []

    
    session = boto3.Session(profile_name=AWS_PROFILE)

    if AWS_REGION == "all":
        c = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in c.describe_regions()['Regions']]
    else:
        regions = [AWS_REGION]

    affected_resources = []

    for region in regions:
        try:
            sgs = get_sgs(session=session, region=region)
        except Exception as e:
            print(f"[*] Region {region} being skipped due to error : {e}")
            continue
    
        for sg in sgs:
            sg_id = sg["GroupId"]
            if sg_id in EXCEPTION_SG_IDS:
                continue
            # We are bothered only about ingress as of now
            if sg.get("IpPermissions"):
                for permission in sg.get("IpPermissions"):
                    exceptions = None
                    exceptions = process_permission(permission=permission, session=session, region=region, sg_id=sg_id)
                    if exceptions:
                        affected_resource = deepcopy(sg)
                        affected_resource.update(exceptions)
                        affected_resource.update({"region": region})
                        affected_resource.update({"guardian:matched_ip_permission": [permission]})
                        affected_resources.append(affected_resource)
                        exceptions = None
        
                    
    if affected_resources:
        
        if FORMAT == "json":
            with open(OUTPUT_PATH, "w") as w:
                w.write(json.dumps({"resources" : affected_resources}, indent=4, default=__json_serial))
        else:
            csv_fields = ["Region", 'SecurityGroup Id','SecurityGroup Name','SecurityGroup Description', 'Allowed Protocol', 'Permission Description', 'Allowed IP(s) / Network(s) / Prefix List(s)','Allowed FromPort','Allowed ToPort', 'Observations']
            out = open(OUTPUT_PATH, 'w')
            writer = csv.DictWriter(out, fieldnames=csv_fields, doublequote=True, quotechar='"', delimiter = ',', quoting = csv.QUOTE_MINIMAL)
            writer.writeheader()
            for r in affected_resources:
                observation = dict()
                observation["Region"] = r["region"]
                observation['SecurityGroup Id'] = r["GroupId"]
                observation['SecurityGroup Name'] = r.get("GroupName")
                observation['SecurityGroup Description'] = r.get("Description")
                observation["Observations"] = ""
                
                if r.get("guardian:unshared_prefix_list_in_usage"):
                    observation["Observations"] += "Unshared prefix list referenced. Affected Prefix Lists:" + ", ".join(r.get("guardian:unshared_prefix_list_in_usage")) + "\r"
                
                if r.get("guardian:exposed_sg_attached_to_non-elbs"):
                    observation["Observations"] += "Non loadbalancer resources exposed. Affected Resource metadata:" + ", ".join(r.get("guardian:exposed_sg_attached_to_non-elbs")) + "\r"
                
                if r.get("guardian:unauthorised_protocol_exposed_to_world"):
                    observation["Observations"] += "Unauthorised protocol exposed to world. Affected protocol: " + ", ".join(r.get("guardian:unauthorised_protocol_exposed_to_world")) + "\r"
                    
                if r.get("guardian:unauthorised_exposure_to_public_ips"):
                    observation["Observations"] += "Exposure to unauthorised public IPs. Affected IP(s): " + ", ".join(r.get("guardian:unauthorised_exposure_to_public_ips")) + "\r"

                if r.get("guardian:unauthorised_ports_exposed_to_world"):
                    observation["Observations"] += "Unauthorised ports exposed to world. Affected ports: " + ", ".join(r.get("guardian:unauthorised_ports_exposed_to_world")) + "\r"
		    
                for perm in r['guardian:matched_ip_permission']:
                
                    if perm["IpProtocol"] == "-1" :
                        observation['Allowed Protocol'] = "All protocols (-1)"
                    else:
                        observation['Allowed Protocol'] = perm["IpProtocol"]
                    
                    if perm.get('IpRanges'):
                        observation['Permission Description'] = perm['IpRanges'][0].get('Description', "None")
                        observation['Allowed IP(s) / Network(s) / Prefix List(s)'] = ", ".join([i["CidrIp"] for i in perm['IpRanges']])
                    elif perm.get('Ipv6Ranges'):
                        observation['Permission Description'] = perm['Ipv6Ranges'][0].get('Description', "None")
                        observation['Allowed IP(s) / Network(s) / Prefix List(s)'] = ", ".join([i["CidrIpv6"] for i in perm['Ipv6Ranges']])
                    elif perm.get('PrefixListIds'):
                        observation['Permission Description'] = perm['PrefixListIds'][0].get('Description', "None")
                        observation['Allowed IP(s) / Network(s) / Prefix List(s)'] = ", ".join([i["PrefixListId"] for i in perm['PrefixListIds']])

                    if perm['IpProtocol'] == '-1':
                        observation['Allowed FromPort'] = str(perm.get("FromPort")) + " (i.e. 0)"
                        observation['Allowed ToPort'] = str(perm.get("ToPort")) + " (i.e. 65535)"
                    else:
                        if perm['IpProtocol'] == "icmp":
                            if perm["FromPort"] in [-1, "-1"]:
                                observation['Allowed FromPort'] = str(perm.get("FromPort")) + "(i.e All ICMP Types allowed)"
                                observation['Allowed ToPort'] = str(perm.get("ToPort")) + " (Not Applicable)"
                            else:
                                observation['Allowed FromPort'] = str(perm.get("FromPort")) + " (i.e Allows only ICMP type '" + str(perm["FromPort"]) + "')"
                                if perm["ToPort"] in [-1, "-1"]:
                                    observation['Allowed ToPort'] = str(perm.get("ToPort")) + " (i.e All ICMP Code for the allowed ICMP type(s) are allowed)"
                                else:
                                    observation['Allowed ToPort'] = str(perm.get("ToPort")) + " (i.e Allows only ICMP code '" + str(perm['ToPort']) + "')"
                        
                        elif perm['IpProtocol'] == "icmpv6":
                            observation['Allowed FromPort'] = str(perm.get("FromPort")) + "(i.e All ICMP Types allowed)"
                            observation['Allowed ToPort'] = str(perm.get("ToPort")) + " (i.e All ICMP Code for the allowed ICMP type(s) are allowed)"
                        
                        else:
                            observation['Allowed FromPort'] = str(perm.get("FromPort"))
                            observation['Allowed ToPort'] = str(perm.get("ToPort"))
                writer.writerow(observation)
            out.close()
