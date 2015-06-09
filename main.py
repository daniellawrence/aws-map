#!/usr/bin/env python
import argparse
import boto.vpc
import boto.ec2
import boto.ec2.elb
import random
import string
import logging
import traceback
import os
import sys

log = logging.getLogger('mapper')
ch = logging.FileHandler('mapper.log', mode='w')
ch.setLevel(logging.DEBUG)
log.addHandler(ch)
log.setLevel(logging.DEBUG)


class AWSMap:
    def __init__(self, region, show_ip=False, show_storage=False, **kwargs):
        self.region = region
        self.connection_kwargs = kwargs
        self._vpc_conn = None
        self._ec2_conn = None
        self._show_ip = show_ip
        self._show_storage = show_storage
        self._load_balancers = None

    @property
    def vpc_conn(self):
        if self._vpc_conn is None:
            self._vpc_conn = boto.vpc.connect_to_region(self.region, **self.connection_kwargs)
        return self._vpc_conn

    @property
    def ec2_conn(self):
        if self._ec2_conn is None:
            self._ec2_conn = boto.ec2.connect_to_region(self.region, **self.connection_kwargs)
        return self._ec2_conn

    @property
    def load_balancers(self):
        if self._load_balancers is None:
            self._load_balancers = boto.ec2.elb.connect_to_region(self.region, **self.connection_kwargs)\
                .get_all_load_balancers()
        return self._load_balancers

    def get_vpcs(self):
        vpc_list = self.vpc_conn.get_all_vpcs()
        log.debug("Getting VPCs...")
        tb = traceback.format_list(traceback.extract_stack())
        [log.debug(t) for t in tb]

        vpcs = []

        for i, v in enumerate(vpc_list):
            if 'Name' not in v.tags:
                continue

            if v.tags['Name'] == 'NOT_USED':
                continue

            cidr_block = v.cidr_block
            name = v.tags['Name']
            log.debug('VPC {i} of {len}: {name}'.format(i=i + 1, len=len(vpc_list), name=name))

            subnet_list = self.get_subnet_list(vpc_id=v.id)
            igw_list = self.get_all_internet_gateways()
            vo = VPC(v.id, name, cidr_block, child=subnet_list + igw_list)
            vpcs.append(vo)
        return vpcs

    def to_graph(self):
        # vpcs = self.get_vpcs()
        vpcs = [vpc.dot() for vpc in self.get_vpcs()]
        return '''
            digraph G {{
                node [shape="dotted",label="",width=0,height=0];
                overlap=false
                ranksep=1.6
                splines=ortho
                {graph}
            }}
        '''.format(graph="\n".join(vpcs))

    def get_subnet_list(self, vpc_id):
        raw_subnet_list = self.vpc_conn.get_all_subnets(filters={'vpc_id': vpc_id})
        subnet_list = []

        for s in raw_subnet_list:
            id = s.id
            cidr_block = s.cidr_block
            if 'Name' in s.tags:
                name = s.tags['Name']
            else:
                name = cidr_block

            if self._show_ip:
                children = self.get_network_interfaces(filters={'subnet_id': id})
            else:
                children = self.get_ec2_list(filters={'subnet_id': id})

            children += [elb for elb in self.get_elbs_for_vpc(vpc_id) if s.id in elb.object.subnets]

            so = Subnet(id, name, cidr_block, child=children)

            subnet_list.append(so)

        return subnet_list

    def get_network_interfaces(self, filters={}):
        if_list = self.ec2_conn.get_all_network_interfaces(filters=filters)
        network_interface_list = []
        for n in if_list:
            id = n.id
            name = get_name(n)
            ip = n.private_ip_address

            if n.attachment and n.attachment.instance_id:
                instance_id = n.attachment.instance_id

                instance_list = self.get_ec2_list(filters={'instance_id': instance_id})

                no = Network(id, name, ip, child=instance_list)
                network_interface_list.append(no)

        return network_interface_list

    def get_ec2_list(self, **kwargs):
        ec2_list = self.ec2_conn.get_all_instances(**kwargs)
        instance_list = []
        for r in ec2_list:
            for i in r.instances:
                id = i.id
                name = get_name(i)
                ip = i.private_ip_address

                volume_list = []
                if self._show_storage:
                    volume_list = self.get_volume_list(filters={'attachment.instance-id': id})

                instance_list.append(Instance(id, name, ip, volume_list))

        return instance_list

    def get_volume_list(self, filters={}):
        bd_list = self.ec2_conn.get_all_volumes(filters=filters)
        volume_list = []
        for bd in bd_list:
            id = bd.id
            name = get_name(bd)
            ip = "%d GB" % bd.size
            so = Storage(id, name, ip)
            volume_list.append(so)
        return volume_list

    def get_all_internet_gateways(self, filters={}):
        raw_igw_list = self.vpc_conn.get_all_internet_gateways(filters=filters)
        igw_list = []
        for igw in raw_igw_list:
            id = igw.id
            if 'Name' in igw.tags:
                name = igw.tags['Name']
            else:
                name = igw.id
            ip = ""
            io = InternetGateWay(id, name, ip)
            igw_list.append(io)
        return igw_list

    def get_elbs_for_vpc(self, vpc_id):
        elbs = []

        for elb in self.load_balancers:
            if elb.vpc_id == vpc_id:
                if elb.instances:
                    instances = self.get_ec2_list(instance_ids=[inst.id for inst in elb.instances])
                else:
                    instances = []

                elbs.append(ELB(elb.name, elb.name, ', '.join(elb.subnets), instances, object=elb))

        return elbs

SHOW_IMAGES = True
CHILD_SUBGRAPH = False

global SUBCLUSTER_ID
SUBCLUSTER_ID = 0

image_root = './icons'

image_map = {
    'Storage': '/Storage & Content Delivery/SVG/Storage & Content Delivery_Amazon EBS Volume.svg.png',
    #'Instance': '/Compute & Networking/SVG/Compute & Networking copy_Amazon EC2--.svg.png',
    'Instance': '/Compute & Networking/SVG/Compute & Networking_Amazon EC2 Instances.svg.png',
    'VPC': '/Non-Service Specific/SVG/Non-Service Specific copy_Virtual Private CLoud .svg.png',
    'Network': '/Compute & Networking/SVG/Compute & Networking_Elastic Network Instance.svg.png',
    'InternetGateWay': '/Compute & Networking/SVG/Compute & Networking_Amazon VPC Internet Gateway.svg.png',
    'ELB': '/Compute & Networking/SVG/Compute & Networking_Elastic Load Balancing.svg.png',
    }


def random_str(len=6):
    return ''.join(random.choice(string.letters + string.digits) for x in range(len))


def random_num(len=3):
    return ''.join(random.choice(string.digits) for x in range(len))


class Dot(object):
    NODE_LIST = []
    SHAPE = 'box'

    def __init__(self, id, name, ip, child=[], object=None):
        self.id = id.replace("-", "_").replace('.', '_')
        self.name = name
        self.ip = ip
        self.child = child
        self.object = object
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

        related_children = []
        for c in self.child:
            if c.id not in Dot.NODE_LIST:
                related_children.append("%s -> %s\n%s\n" % (self.id, c.id, c.dot()))
                Dot.NODE_LIST.append(c.id)
            else:
                related_children.append("%s -> %s" % (self.id, c.id))
        s = "\n\n".join(related_children)

        style = 'rounded'
        shape = getattr(self.__class__, 'SHAPE')

        return '\t\t%s [label="%s"%s,style=%s,shape=%s];\n%s' % (self.id, self, self.image(), style, shape, s)

    def cdot(self):
        cdots = [c.dot() for c in self.child]
        return "\n".join(cdots)

class Storage(Dot):
    pass

class Instance(Dot):
    SHAPE = 'box3d'

class Network(Dot):
    pass

class ELB(Dot):
    pass

class Subnet(Dot):

    def setup(self):
        global SUBCLUSTER_ID
        SUBCLUSTER_ID+=1
        self.SUBCLUSTER_ID = SUBCLUSTER_ID

class VPC(Dot):
    def xdot(self):

        return """

        subgraph cluster_%d {
%s
            label = "%s (%s)"%s;
        }

        """ % (self.SUBCLUSTER_ID,
               self.cdot(),
               self.name,
               self.ip,
               self.image())
    pass

class InternetGateWay(Dot):
    pass

MAP = {}

def get_name(obj):
    if 'Name' in obj.tags:
        return obj.tags['Name']
    return "%s" % obj.id








def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--region')

    opts = parser.parse_args()

    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_access = os.environ.get("AWS_SECRET_ACCESS_KEY")

    if access_key is None or secret_access is None:
        log.warn("AWS Creds required")
        sys.exit(1)

    aws_map = AWSMap(opts.region, aws_access_key_id=access_key, aws_secret_access_key=secret_access)
    print aws_map.to_graph()

if __name__ == '__main__':
    main()
