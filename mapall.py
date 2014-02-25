#!/usr/bin/env python
import sys
import argparse
import boto.vpc
import boto.ec2
import boto.ec2.elb
import boto.rds
from local_settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

image_root = '/home/dannyla/Downloads/AWS_Simple_Icons_svg_eps'

image_map = {
    'Storage': '/Storage & Content Delivery/SVG/Storage & Content Delivery_Amazon EBS Volume.svg.png',
    # 'Instance': '/Compute & Networking/SVG/Compute & Networking copy_Amazon EC2--.svg.png',
    'Instance': '/Compute & Networking/SVG/Compute & Networking copy_Amazon EC2 Instances.svg.png',
    'Subnet': '',  # /Compute & Networking/SVG/Compute & Networking copy_Elastic Network Instance.svg.png',
    'Network': '/Compute & Networking/SVG/Compute & Networking copy_Elastic Network Instance.svg.png',
    'InternetGateWay': '/Compute & Networking/SVG/Compute & Networking copy_Amazon VPC Internet Gateway.svg.png'
    }

objects = {}
clusternum = 0

options = {
    'security_groups': False
}


###############################################################################
###############################################################################
###############################################################################
class Dot(object):
    def __init__(self, args):
        self.args = args

    ##########################################################################
    def draw(self):
        self.args.outputfile.write('%s [label="%s:%s"];\n' % (self.mn(self.id), self.__class__.__name__, self.id))

    ##########################################################################
    def mn(self, s):
        """ Munge name to be dottable """
        s = s.replace('-', '_')
        s = s.replace("'", '"')
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
        self.args.outputfile.write("%s -> %s %s;\n" % (self.mn(a), self.mn(b), blockstr))

    ##########################################################################
    def image(self):
        _type = self.__class__.__name__
        image = ""
        if _type in image_map:
            image = ',image="%s%s"' % (image_root, image_map[_type])
        return image


###############################################################################
###############################################################################
###############################################################################
class Instance(Dot):
    def __init__(self, instance, args):
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
        self.args = args

    def draw(self):
        global clusternum
        if self.args.vpc and self.vpc_id != self.args.vpc:
            return
        self.args.outputfile.write('subgraph cluster%d {\n' % clusternum)
        if 'Name' in self.tags:
            self.args.outputfile.write('label = "%s"\n' % self.tags['Name'])
        self.args.outputfile.write('%s [shape=box, label="%s"];\n' % (self.mn(self.id), self.id))

        extraconns = []
        for o in objects.values():
            if o.partOfInstance(self.id):
                self.connect(self.id, o.id)
                extraconns = o.subclusterDraw()
        self.args.outputfile.write('}\n')
        if self.subnet_id:
            self.connect(self.id, self.subnet_id)
        for ic, ec in extraconns:
            self.connect(ic, ec)
        clusternum += 1


###############################################################################
###############################################################################
###############################################################################
class Subnet(Dot):
    def __init__(self, subnet, args):
        self.id = subnet.id
        self.vpc_id = subnet.vpc_id
        self.cidr_block = subnet.cidr_block
        self.availability_zone = subnet.availability_zone
        self.args = args

    def draw(self):
        if self.args.vpc and self.vpc_id != self.args.vpc:
            return
        self.args.outputfile.write('%s [shape=box, label="%s\n%s"];\n' % (self.mn(self.id), self.id, self.cidr_block))
        self.connect(self.id, self.vpc_id)


###############################################################################
###############################################################################
###############################################################################
class Volume(Dot):
    def __init__(self, vol, args):
        self.id = vol.id
        self.size = vol.size
        self.region = vol.region
        self.status = vol.status
        self.tags = vol.tags
        self.attachment_state = vol.attachment_state()
        self.volume_state = vol.volume_state()
        self.instance_id = vol.attach_data.instance_id
        self.args = args

    def partOfInstance(self, instid):
        return instid == self.instance_id

    def draw(self):
        if not self.attachment_state:
            self.args.outputfile.write('%s [shape=box, label="Unattached Volume:%s\n%s Gb"];\n' % (self.mn(self.id), self.id, self.size))

    def subclusterDraw(self):
        self.args.outputfile.write('%s [shape=box, label="%s\n%s Gb"];\n' % (self.mn(self.id), self.id, self.size))
        return []


###############################################################################
###############################################################################
###############################################################################
class SecurityGroup(Dot):
    def __init__(self, sg, args):
        self.id = sg.id
        self.name = sg.name
        self.args = args

    def draw(self):
        self.args.outputfile.write('%s [shape=box, label="SG: %s"];\n' % (self.mn(self.id), self.name))


###############################################################################
###############################################################################
###############################################################################
class VPC(Dot):
    def __init__(self, vpc, args):
        self.id = vpc.id
        self.state = vpc.state
        self.tags = vpc.tags
        self.args = args


###############################################################################
###############################################################################
###############################################################################
class NetworkInterface(Dot):
    def __init__(self, nic, args):
        self.id = nic.id
        self.subnet_id = nic.subnet_id
        self.privateDnsName = nic.privateDnsName
        self.private_ip_address = nic.private_ip_address
        self.status = nic.status
        self.groups = nic.groups
        self.instance_id = nic.attachment.instance_id
        self.args = args

    def partOfInstance(self, instid):
        return instid == self.instance_id

    def draw(self):
        pass

    def subclusterDraw(self):
        self.args.outputfile.write('%s [shape=box, label="NIC: %s\n%s"];\n' % (self.mn(self.id), self.id, self.private_ip_address))
        externallinks = []
        if options['security_groups']:
            for g in self.groups:
                externallinks.append((self.id, g.id))
        return externallinks


###############################################################################
###############################################################################
###############################################################################
class InternetGateway(Dot):
    def __init__(self, igw, args):
        self.id = igw.id
        self.connection = igw.connection
        self.tags = igw.tags
        self.conns = []
        for i in igw.attachments:
            self.conns.append(i.vpc_id)
        self.args = args

    def draw(self):
        if self.args.vpc:
            for i in self.conns[:]:
                if i != self.args.vpc:
                    self.conns.remove(i)
        if self.conns:
            self.args.outputfile.write('%s [shape=box, label="InternetGateway: %s"];\n' % (self.mn(self.id), self.id))
            for i in self.conns:
                self.connect(self.id, i)


###############################################################################
###############################################################################
###############################################################################
class LoadBalancer(Dot):
    def __init__(self, lb, args):
        self.id = lb.name
        self.name = lb.name
        self.instances = lb.instances
        self.dns_name = lb.dns_name
        self.vpc_id = lb.vpc_id
        self.args = args

    def draw(self):
        if self.args.vpc and self.vpc_id != self.args.vpc:
            return
        self.args.outputfile.write('%s [shape=box, label="ELB: %s"];\n' % (self.mn(self.id), self.id))
        for i in self.instances:
            self.connect(self.id, i.id)


###############################################################################
###############################################################################
###############################################################################
class Database(Dot):
    def __init__(self, db, args):
        self.id = db.id
        self.status = db.status
        self.engine = db.engine
        self.securityid = db.VpcSecurityGroupId
        self.args = args

    def draw(self):
        self.args.outputfile.write('%s [shape=box, label="DB: %s\n%s\n%s"];\n' % (self.mn(self.id), self.id, self.engine, self.status))


###############################################################################
def get_all_internet_gateways(vpc_conn, args, filters={}):
    igw_list = vpc_conn.get_all_internet_gateways(filters=filters)
    for igw in igw_list:
        g = InternetGateway(igw, args)
        objects[g.id] = g


###############################################################################
def get_vpc_list(vpc_conn, args):
    vpc_list = vpc_conn.get_all_vpcs(vpc_ids=args.vpc)
    for vpc in vpc_list:
        g = VPC(vpc, args)
        objects[g.id] = g


###############################################################################
def get_all_instances(vpc_conn, args, filters={}):
    reservation_list = vpc_conn.get_all_instances(filters=filters)
    for reservation in reservation_list:
        for instance in reservation.instances:
            i = Instance(instance, args)
            objects[i.id] = i


###############################################################################
def get_all_subnets(vpc_conn, args, filters={}):
    subnets = vpc_conn.get_all_subnets(filters=filters)
    for subnet in subnets:
        s = Subnet(subnet, args)
        objects[s.id] = s


###############################################################################
def get_all_volumes(vpc_conn, args, filters={}):
    volumes = vpc_conn.get_all_volumes(filters=filters)
    for vol in volumes:
        v = Volume(vol, args)
        objects[v.id] = v


###############################################################################
def get_all_security_groups(vpc_conn, args, filters={}):
    sgs = vpc_conn.get_all_security_groups(filters=filters)
    for sg in sgs:
        s = SecurityGroup(sg, args)
        objects[s.id] = s


###############################################################################
def get_all_network_interfaces(vpc_conn, args, filters={}):
    nics = vpc_conn.get_all_network_interfaces(filters=filters)
    for nic in nics:
        n = NetworkInterface(nic, args)
        objects[n.id] = n


###############################################################################
def get_all_rds(rds_conn, args, filter={}):
    dbs = rds_conn.get_all_dbinstances()
    for db in dbs:
        rds = Database(db, args)
        objects[rds.id] = rds


###############################################################################
def get_all_elbs(elb_conn, args, filter={}):
    elbs = elb_conn.get_all_load_balancers()
    for elb in elbs:
        lb = LoadBalancer(elb, args)
        objects[lb.id] = lb


###############################################################################
def map_region(args):
    # VPC
    vpc_conn = boto.vpc.connect_to_region(args.region,
                                          aws_access_key_id=AWS_ACCESS_KEY_ID,
                                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    get_vpc_list(vpc_conn, args)
    get_all_internet_gateways(vpc_conn, args)
    get_all_network_interfaces(vpc_conn, args)
    get_all_instances(vpc_conn, args)
    get_all_subnets(vpc_conn, args)
    get_all_volumes(vpc_conn, args)
    if options['security_groups']:
        get_all_security_groups(vpc_conn, args)

    # RDS
    rds_conn = boto.rds.connect_to_region(
        args.region,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    get_all_rds(rds_conn, args)

    # ELB
    for r in boto.ec2.elb.regions():
        if r.name == args.region:
            elb_conn = boto.ec2.elb.ELBConnection(
                region=r,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            get_all_elbs(elb_conn, args)
        else:
            continue


###############################################################################
def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vpc', default=None, help="Which VPC to examine [all]")
    parser.add_argument('--region', default='ap-southeast-2', help="Which region to examine [all]")
    parser.add_argument('--outputfile', default=sys.stdout, type=argparse.FileType('w'), help="Which file to output to (stdout)")
    args = parser.parse_args()
    return args


###############################################################################
def main():
    args = parseArgs()
    map_region(args)
    args.outputfile.write("digraph G {\n")
    args.outputfile.write('overlap=false\n')
    args.outputfile.write('ranksep=1.6\n')
    for obj in objects.values():
        obj.draw()
    args.outputfile.write("}\n")


###############################################################################
if __name__ == '__main__':
    main()

#EOF
