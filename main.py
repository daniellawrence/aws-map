#!/usr/bin/env python
import boto.vpc
import boto.ec2
import random
import string
from local_settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

SHOW_IP = True
SHOW_STORAGE = True
SHOW_IMAGES = True
CHILD_SUBGRAPH = False
HARD_RANK = True
NODE= 'node [shape="dotted",label="",width=0,height=0];'


global SUBCLUSTER_ID
SUBCLUSTER_ID = 0

image_root = '/home/dannyla/Downloads/AWS_Simple_Icons_svg_eps'

image_map = {
    'Storage': '/Storage & Content Delivery/SVG/Storage & Content Delivery_Amazon EBS Volume.svg.png',
    #'Instance': '/Compute & Networking/SVG/Compute & Networking copy_Amazon EC2--.svg.png',
    'Instance': '/Compute & Networking/SVG/Compute & Networking copy_Amazon EC2 Instances.svg.png',
    'Subnet': '',#/Compute & Networking/SVG/Compute & Networking copy_Elastic Network Instance.svg.png',
    'Network': '/Compute & Networking/SVG/Compute & Networking copy_Elastic Network Instance.svg.png',
    'InternetGateWay': '/Compute & Networking/SVG/Compute & Networking copy_Amazon VPC Internet Gateway.svg.png'
    }


def random_str(len=6):
    return ''.join(random.choice(string.letters + string.digits) for x in range(len))


def random_num(len=3):
    return ''.join(random.choice(string.digits) for x in range(len))


class Dot(object):
    def __init__(self, id, name, ip, child=[]):
        self.id = id.replace("-","_")
        self.name = name
        self.ip = ip
        self.child = child
        self.setup()
        #self.random()

    def random(self):
        self.id = random_str(6)
        self.name = random_str(10)
        self.ip = "%s.%s.%s.%s" % (random_num(), random_num(), random_num(), random_num())

    def __str__(self):
        lines = ""
        if self.image():
            lines = "\\n"*4
        return "%s%s\\n(%s)" % (lines, self.name, self.ip)

    def setup(self):
        pass

    def image(self):
        if not SHOW_IMAGES:
            return ""
        _type = self.__class__.__name__
        image = ""
        if _type in image_map:
            image = ',image="%s%s"' % (image_root, image_map[_type])
        return image


    def dot(self):
        if CHILD_SUBGRAPH and 'xdot' in dir(self):
            return self.xdot()

        related_childern = []
        for c in self.child:
            related_childern.append("%s -> %s\n%s\n" % ( self.id, c.id, c.dot()))
        s = "\n\n".join(related_childern)
        style = 'dotted'
        if self.image():
            style = 'dashed'
        return '\t\t%s [label="%s"%s,style=%s];\n%s' % (self.id, self, self.image(), style,s)

    def cdot(self):
        cdots = [ c.dot() for c in self.child ]
        return "\n".join(cdots)

class Storage(Dot):
    pass

class Instance(Dot):
    pass

class Network(Dot):
    pass

class Subnet(Instance):

    def setup(self):
        global SUBCLUSTER_ID
        SUBCLUSTER_ID+=1
        self.SUBCLUSTER_ID = SUBCLUSTER_ID

class VPC(Subnet):
    def xdot(self):

        return """

        subgraph cluster_%d {
%s
            label = "%s (%s)";
        }

        """ % (self.SUBCLUSTER_ID,
               self.cdot(),
               self.name,
               self.ip)
    pass

class InternetGateWay(Dot):
    pass

MAP = {}

def get_name(obj):
    if 'Name' in obj.tags:
        return obj.tags['Name']
    return "%s" % obj.id

def get_volume_list(ec2_conn, filters={}):
    bd_list = ec2_conn.get_all_volumes(filters=filters)
    volume_list = []
    for bd in bd_list:
        id = bd.id
        name = get_name(bd)
        #name = bd.tags['Name']
        ip = "%d GB" % bd.size
        so = Storage(id, name, ip)
        volume_list.append(so)
    return volume_list

def get_network_interfaces(ec2_conn, filters={}):
    if_list = ec2_conn.get_all_network_interfaces(filters=filters)
    network_interface_list = []
    for n in if_list:
        id = n.id
        name = get_name(n)
        ip = n.private_ip_address

        instance_id = n.attachment.instance_id

        instance_list = get_ec2_list(ec2_conn, filters={'instance_id': instance_id})
        no = Network(id, name, ip, child=instance_list)
        network_interface_list.append(no)

    return network_interface_list




def get_ec2_list(ec2_conn, filters={}):
    ec2_list = ec2_conn.get_all_instances(filters=filters)
    instance_list = []
    for r in ec2_list:
        for i in r.instances:
            id = i.id
            name = i.tags['Name']
            ip = i.private_ip_address

            volume_list = []
            if SHOW_STORAGE:
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

        if SHOW_IP:
            childern_list = get_network_interfaces(ec2_conn, filters={'subnet_id': id})
        else:
            childern_list = get_ec2_list(ec2_conn, filters={'subnet_id': id})
        so = Subnet(id, name, cidr_block, child=childern_list)

        #print so.dot()
        subnet_list.append(so)
        #print "subcluster_%s -> igw_a51935cc;" % so.SUBCLUSTER_ID

    return subnet_list

def get_all_internet_gateways(vpc_conn, filters={}):
    raw_igw_list = vpc_conn.get_all_internet_gateways(filters=filters)
    igw_list = []
    for igw in raw_igw_list:
        id = igw.id
        name = igw.tags['Name']
        ip = ""
        io = InternetGateWay(id, name, ip)
        igw_list.append(io)
    return igw_list


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
        igw_list = get_all_internet_gateways(vpc_conn)
        vo = VPC(v.id, name, cidr_block, child=subnet_list + igw_list)
        print vo.dot()


def map_region(region_name):
    vpc_conn = boto.vpc.connect_to_region(region_name,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    get_vpc_list(vpc_conn)

def main():
    print "digraph G {"
    #print 'node [shape="none",label="",width=0,height=0];'
    print NODE
    print 'overlap=false'
    print 'ranksep=1.6'
    #map_region('ap-southeast-1')
    map_region('ap-southeast-2')
    print "}"

if __name__ == '__main__':
    main()
