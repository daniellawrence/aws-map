#!/usr/bin/env python
import boto.vpc
import boto.ec2
from local_settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

global SUBCLUSTER_ID
SUBCLUSTER_ID = 0

class Dot(object):
    def __init__(self, id, name, ip, child=[]):
        self.id = id.replace("-","_")
        self.name = name
        self.ip = ip
        self.child = child

    def __str__(self):
        return "%s (%s)" % (self.name, self.ip)

    def dot(self):
        return '\t\t%s [label="%s"];' % (self.id, self)

    def cdot(self):
        cdots = [ c.dot() for c in self.child ]
        return "\n".join(cdots)

class Storage(Dot):
    pass

class Instance(Dot):
    def dot(self):
        global SUBCLUSTER_ID
        SUBCLUSTER_ID+=1
        return """
        
        subgraph cluster_%d {
%s
            label = "%s (%s)";
        }
        
        """ % (SUBCLUSTER_ID,
               self.cdot(),
               self.name,
               self.ip)

class Subnet(Instance):
    pass

class VPC(Subnet):
    pass

MAP = {}

def get_volume_list(ec2_conn, filters={}):
    bd_list = ec2_conn.get_all_volumes(filters=filters)
    volume_list = []
    for bd in bd_list:
        id = bd.id
        name = bd.tags['Name']
        ip = "%d GB" % bd.size
        so = Storage(id, name, ip)
        volume_list.append(so)
    return volume_list

def get_ec2_list(ec2_conn, filters={}):
    ec2_list = ec2_conn.get_all_instances(filters=filters)
    instance_list = []
    for r in ec2_list:
        for i in r.instances:
            id = i.id
            name = i.tags['Name']
            ip = i.private_ip_address
            volume_list = get_volume_list(ec2_conn,filters={'attachment.instance-id': id})
            instance_list.append(Instance(id, name, ip, volume_list))
    return instance_list

def get_subnet_list(vpc_conn, vpc_id):
    raw_subnet_list = vpc_conn.get_all_subnets(filters={'vpc_id': vpc_id})
    subnet_list = []
    
    ec2_conn = boto.ec2.connect_to_region('ap-southeast-2',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    
    for s in raw_subnet_list:
        id = s.id
        cidr_block = s.cidr_block
        name = s.tags['Name']
        #print "\t", name, cidr_block
        instance_list = get_ec2_list(ec2_conn, filters={'subnet_id': id})
        so = Subnet(id, name, cidr_block, child=instance_list)
        #print so.dot()
        subnet_list.append(so)
    return subnet_list
    

def get_vpc_list(vpc_conn):
    vpc_list = vpc_conn.get_all_vpcs()
    
    for v in vpc_list:
        if 'Name' not in v.tags:
            continue

        if v.tags['Name'] == 'NOT_USED':
            continue
            
        cidr_block = v.cidr_block
        name = v.tags['Name']
        
        subnet_list = get_subnet_list(vpc_conn, vpc_id=v.id)
        vo = VPC(v.id, name, cidr_block, child=subnet_list)
        print vo.dot()
        

def map_region(region_name):
    vpc_conn = boto.vpc.connect_to_region(region_name,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    get_vpc_list(vpc_conn)

def main():
    print "digraph G {"
    #map_region('ap-southeast-1')
    map_region('ap-southeast-2')
    print "}"

if __name__ == '__main__':
    main()
