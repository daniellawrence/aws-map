#!/usr/bin/env python
import sys
import boto.vpc
import boto.ec2
import boto.rds
from local_settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

image_root = '/home/dannyla/Downloads/AWS_Simple_Icons_svg_eps'

image_map = {
    'Storage': '/Storage & Content Delivery/SVG/Storage & Content Delivery_Amazon EBS Volume.svg.png',
    #'Instance': '/Compute & Networking/SVG/Compute & Networking copy_Amazon EC2--.svg.png',
    'Instance': '/Compute & Networking/SVG/Compute & Networking copy_Amazon EC2 Instances.svg.png',
    'Subnet': '',#/Compute & Networking/SVG/Compute & Networking copy_Elastic Network Instance.svg.png',
    'Network': '/Compute & Networking/SVG/Compute & Networking copy_Elastic Network Instance.svg.png',
    'InternetGateWay': '/Compute & Networking/SVG/Compute & Networking copy_Amazon VPC Internet Gateway.svg.png'
    }

objects={}
clusternum=0

options = {
  'security_groups': False
}


###############################################################################
###############################################################################
###############################################################################
class Dot(object):
    def __init__(self):
        pass

    ##########################################################################
    def draw(self):
        print '%s [label="%s:%s"];' % (self.mn(self.id), self.__class__.__name__, self.id)

    ##########################################################################
    def mn(self, s):
        """ Munge name to be dottable """
        s=s.replace('-', '_')
        s=s.replace("'",'"')
        return s

    ##########################################################################
    def partOfInstance(self, instid):
        return False

    ##########################################################################
    def connect(self, a, b, **kwargs):
        blockstr = ''
        for kk, kv in kwargs.items():
            blockstr += '%s=%s ' % (kk, kv)
        if blockstr:
            blockstr = '[ %s ]' % blockstr
        print "%s -> %s %s;" % (self.mn(a), self.mn(b), blockstr)


    ##########################################################################
    def image(self):
        if not SHOW_IMAGES:
            return ""
        _type = self.__class__.__name__
        image = ""
        if _type in image_map:
            image = ',image="%s%s"' % (image_root, image_map[_type])
        return image


###############################################################################
###############################################################################
###############################################################################
class Instance(Dot):
    def __init__(self, instance):
       self.id = instance.id
       self.vpc_id = instance.vpc_id
       self.tags = instance.tags
       self.public_dns_name = instance.public_dns_name
       self.private_ip_address = instance.private_ip_address
       self.ip_address = instance.ip_address
       self.image_id = instance.image_id
       self.subnet_id = instance.subnet_id
       self.key_name = instance.key_name
       self.connection = instance.connection
       self.dns_name = instance.dns_name


    def draw(self):
        global clusternum
        print 'subgraph cluster%d {' % clusternum
        print '%s [shape=box, label="%s"];' % (self.mn(self.id), self.id)

        extraconns=[]
        for o in objects.values():
            if o.partOfInstance(self.id):
                self.connect(self.id, o.id)
                extraconns=o.subclusterDraw()
        print '}'
        if self.subnet_id:
            self.connect(self.id, self.subnet_id)
        for ic, ec in extraconns:
            self.connect(ic, ec)
        clusternum+=1

###############################################################################
###############################################################################
###############################################################################
class Subnet(Dot):
    def __init__(self, subnet):
        self.id = subnet.id
        self.vpc_id = subnet.vpc_id
        self.cidr_block = subnet.cidr_block
        self.availability_zone = subnet.availability_zone

    def draw(self):
        print '%s [shape=box, label="%s\n%s"];' % (self.mn(self.id), self.id, self.cidr_block)
        self.connect(self.id, self.vpc_id)


###############################################################################
###############################################################################
###############################################################################
class Volume(Dot):
    def __init__(self, vol):
        self.id = vol.id
        self.size = vol.size
        self.region = vol.region
        self.status = vol.status
        self.tags = vol.tags
        self.attachment_state = vol.attachment_state()
        self.volume_state = vol.volume_state()
        self.instance_id = vol.attach_data.instance_id

    def partOfInstance(self, instid):
        return instid == self.instance_id

    def draw(self):
        if not self.attachment_state:
            print '%s [shape=box, label="Unattached Volume:%s\n%s Gb"];' % (self.mn(self.id), self.id, self.size)

    def subclusterDraw(self):
        print '%s [shape=box, label="%s\n%s Gb"];' % (self.mn(self.id), self.id, self.size)
        return []

###############################################################################
###############################################################################
###############################################################################
class SecurityGroup(Dot):
    def __init__(self, sg):
        self.id = sg.id
        self.name = sg.name

    def draw(self):
        print '%s [shape=box, label="SG: %s"];' % (self.mn(self.id), self.name)

###############################################################################
###############################################################################
###############################################################################
class VPC(Dot):
    def __init__(self, vpc):
        self.id = vpc.id
        self.state = vpc.state
        self.tags = vpc.tags

###############################################################################
###############################################################################
###############################################################################
class NetworkInterface(Dot):
    def __init__(self, nic):
        self.id = nic.id
        self.subnet_id = nic.subnet_id
        self.privateDnsName = nic.privateDnsName
        self.private_ip_address = nic.private_ip_address
        self.status = nic.status
        self.groups = nic.groups
        self.instance_id = nic.attachment.instance_id

    def partOfInstance(self, instid):
        return instid == self.instance_id

    def draw(self):
        pass

    def subclusterDraw(self):
        print '%s [shape=box, label="NIC: %s\n%s\n%s"];' % (self.mn(self.id), self.id, self.private_ip_address, self.status)
        externallinks=[]
        if options['security_groups']:
            for g in self.groups:
                externallinks.append((self.id, g.id))
        return externallinks

###############################################################################
###############################################################################
###############################################################################
class InternetGateway(Dot):
    def __init__(self, igw):
        self.id = igw.id
        self.connection = igw.connection
        self.tags = igw.tags
        self.conns = []
        for i in igw.attachments:
            self.conns.append(i.vpc_id)

    def draw(self):
        print '%s [shape=box, label="InternetGateway: %s"];' % (self.mn(self.id), self.id)
        for i in self.conns:
          self.connect(self.id, i)


###############################################################################
def get_all_internet_gateways(vpc_conn, filters={}):
    igw_list = vpc_conn.get_all_internet_gateways(filters=filters)
    for igw in igw_list:
        g = InternetGateway(igw)
        objects[g.id] = g


###############################################################################
def get_vpc_list(vpc_conn):
    vpc_list = vpc_conn.get_all_vpcs()
    for vpc in vpc_list:
        g = VPC(vpc)
        objects[g.id] = g
        

###############################################################################
def get_all_instances(vpc_conn, filters={}):
    reservation_list = vpc_conn.get_all_instances(filters=filters)
    for reservation in reservation_list:
        for instance in reservation.instances:
            i = Instance(instance)
            objects[i.id] = i


###############################################################################
def get_all_subnets(vpc_conn, filters={}):
    subnets = vpc_conn.get_all_subnets(filters=filters)
    for subnet in subnets:
        s = Subnet(subnet)
        objects[s.id] = s


###############################################################################
def get_all_volumes(vpc_conn, filters={}):
    volumes = vpc_conn.get_all_volumes(filters=filters)
    for vol in volumes:
        v = Volume(vol)
        objects[v.id] = v


###############################################################################
def get_all_security_groups(vpc_conn, filters={}):
    sgs = vpc_conn.get_all_security_groups(filters=filters)
    for sg in sgs:
        s = SecurityGroup(sg)
        objects[s.id] = s


###############################################################################
def get_all_network_interfaces(vpc_conn, filters={}):
    nics = vpc_conn.get_all_network_interfaces(filters=filters)
    for nic in nics:
        n = NetworkInterface(nic)
        objects[n.id] = n


###############################################################################
def get_all_rds(rds_conn, filter={}):
    dbs = rds_conn.get_all_dbinstances()
    for db in dbs:
        sys.stderr.write("Unhandled RDS: %s\n" % db)


###############################################################################
def map_region(region_name):
    vpc_conn = boto.vpc.connect_to_region(region_name,
        aws_access_key_id = AWS_ACCESS_KEY_ID,
        aws_secret_access_key = AWS_SECRET_ACCESS_KEY)
    get_vpc_list(vpc_conn)
    get_all_internet_gateways(vpc_conn)
    get_all_network_interfaces(vpc_conn)
    get_all_instances(vpc_conn)
    get_all_subnets(vpc_conn)
    get_all_volumes(vpc_conn)
    if options['security_groups']:
        get_all_security_groups(vpc_conn)

    rds_conn = boto.rds.RDSConnection(
        aws_access_key_id = AWS_ACCESS_KEY_ID,
        aws_secret_access_key = AWS_SECRET_ACCESS_KEY)
    get_all_rds(rds_conn)

###############################################################################
def main():
    map_region('ap-southeast-2')
    print "digraph G {"
    print 'overlap=false'
    print 'ranksep=1.6'
    for obj in objects.values():
        obj.draw()
    print "}"


###############################################################################
if __name__ == '__main__':
    main()
