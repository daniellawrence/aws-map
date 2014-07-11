#!/usr/bin/env python
#
# Map AWS setup
# Images are available from http://aws.amazon.com/architecture/icons/

import argparse
import json
import md5
import os
import sys

objects = {}
clusternum = 0
awsflags = []
nocache = False


###############################################################################
###############################################################################
###############################################################################
class Dot(object):
    def __init__(self, data, args):
        self.data = data
        self.args = args

    ##########################################################################
    def __getitem__(self, key):
        return self.data.get(key, None)

    ##########################################################################
    def draw(self, fh):
        fh.write('%s [label="%s:%s" %s];\n' % (self.mn(self.name), self.__class__.__name__, self.name, self.image()))

    ##########################################################################
    def mn(self, s=None):
        """ Munge name to be dottable """
        if not s:
            s = self.name
        s = s.replace('-', '_')
        s = s.replace("'", '"')
        return s

    ##########################################################################
    def partOfInstance(self, instid):
        return False

    ##########################################################################
    def inSubnet(self, subnet):
        return True

    ##########################################################################
    def connect(self, fh, a, b, **kwargs):
        blockstr = ''
        for kk, kv in kwargs.items():
            blockstr += '%s=%s ' % (kk, kv)
        if blockstr:
            blockstr = '[ %s ]' % blockstr
        fh.write("%s -> %s %s;\n" % (self.mn(a), self.mn(b), blockstr))

    ##########################################################################
    def tags(self, key=None):
        tagd = {}
        if 'Tags' not in self.data:
            return None
        for t in self['Tags']:
            tagd[t['Key']] = t['Value']
        if key:
            return tagd.get(key, None)
        else:
            return tagd

    ##########################################################################
    def rank(self, fh):
        fh.write(self.mn())

    ##########################################################################
    def image(self, names=[]):
        if not names:
            names = [self.__class__.__name__]
        for name in names:
            imgfile = os.path.join('images', '%s.png' % name)
            if os.path.exists(imgfile):
                imagestr = ', image="%s", shape=none ' % imgfile
                break
        else:
            imagestr = ', shape=box'
        return imagestr


###############################################################################
###############################################################################
###############################################################################
class Instance(Dot):
    """
    u'AmiLaunchIndex': 0
    u'Architecture': u'x86_64',
    u'BlockDeviceMappings': [
        {u'DeviceName': u'/dev/sda1',
        u'Ebs': {u'Status': u'attached', u'DeleteOnTermination': True, u'VolumeId': u'vol-XXXXXXXX', u'AttachTime': u'2000-01-01T01:00:00.000Z'}
        }],
    u'ClientToken': u'stuff',
    u'EbsOptimized': False,
    u'Hypervisor': u'xen',
    u'ImageId': u'ami-XXXXXXXX',
    u'InstanceId': u'i-XXXXXXXX',
    u'InstanceType': u't1.micro',
    u'KernelId': u'aki-XXXXXXXX',
    u'KeyName': u'KeyName',
    u'LaunchTime': u'2000-01-01T01:00:00.000Z',
    u'Monitoring': {u'State': u'disabled'},
    u'NetworkInterfaces': [...],
    u'Placement': {u'GroupName': None, u'Tenancy': u'default', u'AvailabilityZone': u'ap-southeast-2a'},
    u'PrivateDnsName': u'ip-10-1-2-3.ap-southeast-2.compute.internal',
    u'PrivateIpAddress': u'10.1.2.3',
    u'ProductCodes': [],
    u'PublicDnsName': u'ec2-54-1-2-3.ap-southeast-2.compute.amazonaws.com',
    u'PublicIpAddress': u'54.1.2.3',
    u'RootDeviceName': u'/dev/sda1',
    u'RootDeviceType': u'ebs',
    u'SecurityGroups': [{u'GroupName': u'XXX_GroupName_XXX', u'GroupId': u'sg-XXXXXXXX'}, ...
    u'SourceDestCheck': True,
    u'State': {u'Code': 16, u'Name': u'running'},
    u'StateTransitionReason': None,
    u'SubnetId': u'subnet-XXXXXXXX',
    u'Tags': [{u'Key': u'aws:cloudformation:stack-id', u'Value': u'Stuff'},
            {u'Key': u'aws:cloudformation:stack-name', u'Value': u'Stuff'},
            {u'Key': u'Name', u'Value': u'Stuff'},
            {u'Key': u'aws:cloudformation:logical-id', u'Value': u'JumpHost'}],
    u'VirtualizationType': u'paravirtual',
    u'VpcId': u'vpc-XXXXXXXX',
    """
    def __init__(self, instance, args):
        self.data = instance
        self.name = instance['InstanceId']
        self.args = args

    def inSubnet(self, subnet=None):
        if subnet and self['SubnetId'] != subnet:
            return False
        return True

    def inVpc(self, vpc=None):
        if vpc and self['VpcId'] != vpc:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def draw(self, fh):
        global clusternum
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        fh.write('// Instance %s\n' % self.name)
        fh.write('subgraph cluster_%d {\n' % clusternum)
        if self.tags('Name'):
            fh.write('label = "%s"\n' % self.tags('Name'))
        fh.write('%s [label="%s" %s];\n' % (self.mn(self.name), self.name, self.image()))

        extraconns = []
        for o in objects.values():
            if o.partOfInstance(self.name):
                self.connect(fh, self.name, o.name)
                extraconns = o.subclusterDraw(fh)
        fh.write('graph [style=dotted]\n')
        fh.write('}\n')   # End subgraph cluster
        if self['SubnetId']:
            self.connect(fh, self.name, self['SubnetId'])
        for ic, ec in extraconns:
            self.connect(fh, ic, ec)
        clusternum += 1
        if self.args.security:
            for sg in self['SecurityGroups']:
                self.connect(fh, self.name, sg['GroupId'])


###############################################################################
###############################################################################
###############################################################################
class Subnet(Dot):
    """
    u'AvailabilityZone': u'ap-southeast-2a',
    u'AvailableIpAddressCount': 10,
    u'CidrBlock': u'10.1.2.3/28'
    u'DefaultForAz': False,
    u'MapPublicIpOnLaunch': False,
    u'State': u'available',
    u'SubnetId': u'subnet-XXXXXXXX',
    u'Tags': [{u'Key': u'aws:cloudformation:stack-id',
             u'Value': u'arn:aws:cloudformation:ap-southeast-2:XXXXXXXXXXXX:stack/Stuff'},
             {u'Key': u'aws:cloudformation:stack-name', u'Value': u'Stuff'},
             {u'Key': u'aws:cloudformation:logical-id', u'Value': u'SubnetA3'}],
    u'VpcId': u'vpc-XXXXXXXX',
    """
    def __init__(self, subnet, args):
        self.data = subnet
        self.name = subnet['SubnetId']
        self.args = args

    def inVpc(self, vpc):
        if vpc and self['VpcId'] != vpc:
            return False
        return True

    def inSubnet(self, subnet=None):
        if subnet and self['SubnetId'] != subnet:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        fh.write('// Subnet %s\n' % self.name)
        fh.write('%s [label="%s\n%s" %s];\n' % (self.mn(self.name), self.name, self['CidrBlock'], self.image()))
        self.connect(fh, self.name, self['VpcId'])


###############################################################################
###############################################################################
###############################################################################
class Volume(Dot):
    """
    u'Attachments': [
        {u'AttachTime': u'2000-01-01T01:00:00.000Z', u'InstanceId': u'i-XXXXXXXX',
        u'VolumeId': u'vol-XXXXXXXX', u'State': u'attached',
        u'DeleteOnTermination': True, u'Device': u'/dev/sda1'}],
    u'AvailabilityZone': u'ap-southeast-2b',
    u'CreateTime': u'2000-01-01T01:00:00.000Z',
    u'Size': 6
    u'SnapshotId': u'snap-XXXXXXXX',
    u'State': u'in-use',
    u'VolumeId': u'vol-XXXXXXXX',
    u'VolumeType': u'standard',
    """
    def __init__(self, vol, args):
        self.data = vol
        self.name = vol['VolumeId']
        self.args = args

    def partOfInstance(self, instid):
        for a in self['Attachments']:
            if a['InstanceId'] == instid:
                return True
        return False

    def draw(self, fh):
        if self['State'] not in ('in-use',):
            if self.args.vpc:
                return
            if self.args.subnet or self.args.vpc:
                return
            fh.write('%s [label="Unattached Volume:%s\n%s Gb" %s];\n' % (self.mn(self.name), self.name, self['Size'], self.image()))

    def subclusterDraw(self, fh):
        fh.write('%s [shape=box, label="%s\n%s Gb"];\n' % (self.mn(self.name), self.name, self['Size']))
        return []


###############################################################################
###############################################################################
###############################################################################
class SecurityGroup(Dot):
    """
    u'Description': u'SG Description',
    u'GroupId': u'sg-XXXXXXXX'
    u'GroupName': u'XXX_GroupName_XXX',
    u'IpPermissions': [{u'ToPort': 443, u'IpProtocol': u'tcp', u'IpRanges': [{u'CidrIp': u'0.0.0.0/0'}], u'UserIdGroupPairs': [], u'FromPort': 443}],
    u'IpPermissionsEgress': [{u'ToPort': 4502, u'IpProtocol': u'tcp', u'IpRanges': [{u'CidrIp': u'0.0.0.0/0'}], u'UserIdGroupPairs': [], u'FromPort': 4502}],
    u'OwnerId': u'XXXXXXXXXXXX',
    u'Tags': [{u'Key': u'Key', u'Value': u'Value'}, ...
    u'VpcId': u'vpc-XXXXXXXX',
    """
    def __init__(self, sg, args):
        self.data = sg
        self.name = sg['GroupId']
        self.args = args

    def draw(self, fh):
        if self.args.vpc and self['VpcId'] != self.args.vpc:
            return

        portstr = self.permstring(fh, self['IpPermissions'])
        eportstr = self.permstring(fh, self['IpPermissionsEgress'])

        tportstr = []
        if portstr:
            tportstr.append("Ingress: %s" % portstr)
        if eportstr:
            tportstr.append("Egress: %s" % eportstr)
        fh.write('%s [label="SG: %s\n%s\n%s" %s];\n' % (self.mn(self.name), self.name, self["Description"], "\n".join(tportstr), self.image()))

    def permstring(self, fh, obj):
        """
        Convert the permutations and combinations into a sensible output
        """
        ans = []
        if not obj:
            return ''
        for ip in obj:
            if ip['UserIdGroupPairs']:
                for pair in ip['UserIdGroupPairs']:
                    self.connect(fh, self.name, pair['GroupId'])
            if 'FromPort' in ip and ip['FromPort']:
                ipranges = []
                for ipr in ip['IpRanges']:
                    if 'CidrIp' in ipr:
                        ipranges.append(ipr['CidrIp'])
                iprangestr = ';'.join(ipranges)
                ans.append("%s %s->%s/%s" % (iprangestr, ip['FromPort'], ip['ToPort'], ip['IpProtocol']))
        return " ".join(ans)


###############################################################################
###############################################################################
###############################################################################
class VPC(Dot):
    """
    u'CidrBlock': u'172.1.2.3/16',
    u'DhcpOptionsId': u'dopt-XXXXXXXX',
    u'InstanceTenancy': u'default',
    u'IsDefault': True,
    u'State': u'available',
    u'VpcId': u'vpc-XXXXXXXX',
    """
    def __init__(self, vpc, args):
        self.data = vpc
        self.name = vpc['VpcId']
        self.args = args

    def inVpc(self, vpc):
        if vpc and self.name != vpc:
            return False
        return True

    def inSubnet(self, subnet):
        """ Return True if the subnet is in this VPC"""
        if not subnet:
            return True
        if objects[subnet].inVpc(self.name):
            return True
        return False

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        fh.write('%s [label="%s:%s" %s];\n' % (self.mn(self.name), self.__class__.__name__, self.name, self.image()))


###############################################################################
###############################################################################
###############################################################################
class RouteTable(Dot):
    """
    u'Associations': [{u'SubnetId': u'subnet-XXXXXXXX', u'RouteTableAssociationId': u'rtbassoc-XXXXXXXX', u'RouteTableId': u'rtb-XXXXXXXX'}, ...]
    u'PropagatingVgws': [],
    u'RouteTableId': u'rtb-XXXXXXXX',
    u'Routes': [
        {u'GatewayId': u'local', u'DestinationCidrBlock': u'10.1.2.3/23',
            u'State': u'active', u'Origin': u'CreateRouteTable'},
        {u'Origin': u'CreateRoute', u'DestinationCidrBlock': u'0.0.0.0/0',
            u'InstanceId': u'i-XXXXXXXX', u'NetworkInterfaceId': u'eni-XXXXXXXX',
            u'State': u'active', u'InstanceOwnerId': u'XXXXXXXXXXXX'}]
    u'Tags': [{u'Key': u'Key', u'Value': u'Value'}, ...
    u'VpcId': u'vpc-XXXXXXXX',

    """
    def __init__(self, rt, args):
        self.data = rt
        self.args = args
        self.name = self['RouteTableId']

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def inVpc(self, vpc):
        if vpc and self['VpcId'] != vpc:
            return False
        return True

    def inSubnet(self, subnet):
        if not subnet:
            return True
        for a in self['Associations']:
            if subnet == a.get('SubnetId', None):
                return True
        return False

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        routelist = []
        for rt in self['Routes']:
            if 'DestinationCidrBlock' in rt:
                routelist.append(rt['DestinationCidrBlock'])
        fh.write('%s [label="RT: %s\n%s" %s];\n' % (self.mn(), self.name, ";".join(routelist), self.image()))
        for ass in self['Associations']:
            if 'SubnetId' in ass:
                if objects[ass['SubnetId']].inSubnet(self.args.subnet):
                    self.connect(fh, self.name, ass['SubnetId'])
        for rt in self['Routes']:
            if 'InstanceId' in rt:
                if objects[rt['InstanceId']].inSubnet(self.args.subnet):
                    self.connect(fh, self.name, rt['InstanceId'])
            elif 'NetworkInterfaceId' in rt:
                self.connect(fh, self.name, rt['NetworkInterfaceId'])


###############################################################################
###############################################################################
###############################################################################
class NetworkInterface(Dot):
    """
    u'Association': {u'PublicIp': u'54.1.2.3', u'IpOwnerId': u'amazon'}
    u'Attachment': {
        u'Status': u'attached', u'DeviceIndex': 0,
        u'AttachTime': u'2000-01-01T01:00:00.000Z', u'InstanceId': u'i-XXXXXXXX',
        u'DeleteOnTermination': True, u'AttachmentId': u'eni-attach-XXXXXXXX',
        u'InstanceOwnerId': u'XXXXXXXXXXXX'},
    u'AvailabilityZone': u'ap-southeast-2b',
    u'Description': None,
    u'Groups': [{u'GroupName': u'XXX_GroupName_XXX', u'GroupId': u'sg-XXXXXXXX'}],
    u'MacAddress': u'aa:bb:cc:dd:ee:ff',
    u'NetworkInterfaceId': u'eni-XXXXXXXX',
    u'OwnerId': u'XXXXXXXXXXXX',
    u'PrivateDnsName': u'ip-172-1-2-3.ap-southeast-2.compute.internal',
    u'PrivateIpAddress': u'172.1.2.3',
    u'PrivateIpAddresses': [
        {u'PrivateDnsName': u'ip-172-1-2-3.ap-southeast-2.compute.internal',
        u'PrivateIpAddress': u'172.1.2.3', u'Primary': True,
        u'Association': {u'PublicIp': u'54.1.2.3', u'IpOwnerId': u'amazon'}}],
    u'RequesterManaged': False,
    u'SourceDestCheck': True,
    u'Status': u'in-use',
    u'SubnetId': u'subnet-XXXXXXXX',
    u'TagSet': [],
    u'VpcId': u'vpc-XXXXXXXX',
    """
    def __init__(self, nic, args):
        self.data = nic
        self.args = args
        self.name = self['NetworkInterfaceId']

    def partOfInstance(self, instid):
        try:
            return self['Attachment'].get('InstanceId', None) == instid
        except AttributeError:
            return False

    def inSubnet(self, subnet=None):
        if subnet and self['SubnetId'] != subnet:
            return False
        return True

    def draw(self, fh):
        pass

    def subclusterDraw(self, fh):
        fh.write('%s [label="NIC: %s\n%s" %s];\n' % (self.mn(self.name), self.name, self['PrivateIpAddress'], self.image()))
        externallinks = []
        if self.args.security:
            for g in self['Groups']:
                externallinks.append((self.name, g['GroupId']))
        return externallinks


###############################################################################
###############################################################################
###############################################################################
class InternetGateway(Dot):
    """
    u'Attachments': [{u'State': u'available', u'VpcId': u'vpc-XXXXXXXX'}],
    u'InternetGatewayId': u'igw-3a121a58',
    u'Tags': [
        {u'Key': u'aws:cloudformation:stack-id', u'Value': u'arn:aws:cloudformation:ap-southeast-2:XXXXXXXXXXXX:stack/Stuff'},
        {u'Key': u'aws:cloudformation:logical-id', u'Value': u'InternetGateway'},
        {u'Key': u'aws:cloudformation:stack-name', u'Value': u'Stuff'}],
    """
    def __init__(self, igw, args):
        self.data = igw
        self.name = igw['InternetGatewayId']
        self.conns = []
        for i in igw['Attachments']:
            self.conns.append(i['VpcId'])
        self.args = args

    def rank(self, fh):
        if self.args.vpc:
            for i in self.conns[:]:
                if i != self.args.vpc:
                    self.conns.remove(i)
        if self.conns:
            fh.write("%s;" % self.mn())

    def draw(self, fh):
        if self.args.vpc:
            for i in self.conns[:]:
                if i != self.args.vpc:
                    self.conns.remove(i)
        if self.args.subnet:
            for i in self.conns[:]:
                if not objects[i].inSubnet(self.args.subnet):
                    self.conns.remove(i)
        if self.conns:
            fh.write('%s [label="InternetGateway: %s" %s];\n' % (self.mn(self.name), self.name, self.image()))
            for i in self.conns:
                self.connect(fh, self.name, i)


###############################################################################
###############################################################################
###############################################################################
class LoadBalancer(Dot):
    """
    u'AvailabilityZones': [u'ap-southeast-2b', u'ap-southeast-2a'],
    u'BackendServerDescriptions': [],
    u'CanonicalHostedZoneName': u'Stuff',
    u'CanonicalHostedZoneNameID': u'XXXXXXXXXXXXXX',
    u'CreatedTime': u'2000-01-01T01:00:00.300Z',
    u'DNSName': u'Stuff',
    u'HealthCheck': {u'HealthyThreshold': 2, u'Interval': 30, u'Target': u'TCP:7990', u'Timeout': 5, u'UnhealthyThreshold': 2},
    u'Instances': [{u'InstanceId': u'i-XXXXXXXX'}],
    u'ListenerDescriptions': [
        {u'Listener': {
            u'InstancePort': 7990, u'Protocol': u'HTTPS', u'LoadBalancerPort': 443,
            u'SSLCertificateId': u'arn:aws:iam::XXXXXXXXXXXX:server-certificate/GenericSSL',
            u'InstanceProtocol': u'HTTP'}, u'PolicyNames': [u'ELBSecurityPolicy-2011-08']},
        {u'Listener': {
            u'InstancePort': 7999, u'LoadBalancerPort': 7999, u'Protocol': u'TCP',
            u'InstanceProtocol': u'TCP'}, u'PolicyNames': []}],
    u'LoadBalancerName': u'Stuff',
    u'Policies': {u'LBCookieStickinessPolicies': [], u'AppCookieStickinessPolicies': [], u'OtherPolicies': [u'ELBSecurityPolicy-2011-08']},
    u'Scheme': u'internet-facing',
    u'SecurityGroups': [u'sg-XXXXXXXX'],
    u'SourceSecurityGroup': {u'OwnerAlias': u'XXXXXXXXXXXX', u'GroupName': u'XXX_GroupName_XXX'}
    u'Subnets': [u'subnet-XXXXXXXX', u'subnet-XXXXXXXX'],
    u'VPCId': u'vpc-XXXXXXXX',
    """
    def __init__(self, lb, args):
        self.data = lb
        self.name = lb[u'LoadBalancerName']
        self.args = args

    def inSubnet(self, subnet=None):
        if subnet and subnet not in self['Subnets']:
            return False
        return True

    def inVpc(self, vpc):
        if vpc and self['VPCId'] != vpc:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        ports = []
        for l in self['ListenerDescriptions']:
            x = l['Listener']
            ports.append("%s/%s -> %s/%s" % (x['LoadBalancerPort'], x['Protocol'], x['InstancePort'], x['InstanceProtocol']))

        fh.write('%s [label="ELB: %s\n%s" %s];\n' % (self.mn(self.name), self.name, "\n".join(ports), self.image()))
        for i in self['Instances']:
            if objects[i['InstanceId']].inSubnet(self.args.subnet):
                self.connect(fh, self.name, i['InstanceId'])
        for s in self['Subnets']:
            if self.args.subnet:
                if s != self.args.subnet:
                    continue
            self.connect(fh, self.name, s)
        if self.args.security:
            for sg in self['SecurityGroups']:
                self.connect(fh, self.name, sg)


###############################################################################
###############################################################################
###############################################################################
class Database(Dot):
    """
    u'AllocatedStorage': 5,
    u'AutoMinorVersionUpgrade': True,
    u'AvailabilityZone': u'ap-southeast-2a',
    u'BackupRetentionPeriod': 0,
    u'DBInstanceClass': u'db.t1.micro',
    u'DBInstanceIdentifier': u'devapps'
    u'DBInstanceStatus': u'available',
    u'DBName': u'crowd',
    u'DBParameterGroups': [{u'DBParameterGroupName': u'XXX_GroupName_XXX', u'ParameterApplyStatus': u'in-sync'}],
    u'DBSecurityGroups': [],
    u'DBSubnetGroup': {
        u'DBSubnetGroupDescription': u'default',
        u'DBSubnetGroupName': u'default',
        u'SubnetGroupStatus': u'Complete'
        u'Subnets': [
            {
                u'SubnetStatus': u'Active',
                u'SubnetIdentifier': u'subnet-XXXXXXXX',
                u'SubnetAvailabilityZone': {u'Name': u'ap-southeast-2b', u'ProvisionedIopsCapable': False}
            },
            ...
            ],
        u'VpcId': u'vpc-XXXXXXXX',
        },
    u'Endpoint': {u'Port': 3306, u'Address': u'devapps.csgxwe0psnca.ap-southeast-2.rds.amazonaws.com'},
    u'Engine': u'mysql',
    u'EngineVersion': u'5.6.13',
    u'InstanceCreateTime': u'2000-01-01T01:00:00.275Z',
    u'LicenseModel': u'general-public-license',
    u'MasterUsername': u'rootmaster',
    u'MultiAZ': False,
    u'OptionGroupMemberships': [{u'Status': u'in-sync', u'OptionGroupName': u'default:mysql-5-6'}],
    u'PendingModifiedValues': {},
    u'PreferredBackupWindow': u'18:37-19:07',
    u'PreferredMaintenanceWindow': u'sat:15:17-sat:15:47',
    u'PubliclyAccessible': True,
    u'ReadReplicaDBInstanceIdentifiers': [],
    u'VpcSecurityGroups': [{u'Status': u'active', u'VpcSecurityGroupId': u'sg-XXXXXXXX'}],
    """
    def __init__(self, db, args):
        self.data = db
        self.name = db['DBInstanceIdentifier']
        self.args = args

    def inSubnet(self, subnet=None):
        if not subnet:
            return True
        for snet in self['DBSubnetGroup']['Subnets']:
            if subnet == snet['SubnetIdentifier']:
                return True
        return False

    def inVpc(self, vpc):
        if vpc and self['DBSubnetGroup']['VpcId'] != vpc:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        fh.write('// Database %s\n' % self.name)
        imgstr = self.image(["Database-%s" % self['Engine'], 'Database'])
        fh.write('%s [label="DB: %s\n%s" %s];\n' % (self.mn(self.name), self.name, self['Engine'], imgstr))
        for subnet in self['DBSubnetGroup']['Subnets']:
            if subnet['SubnetStatus'] == 'Active':
                if objects[subnet['SubnetIdentifier']].inSubnet(self.args.subnet):
                    self.connect(fh, self.name, subnet['SubnetIdentifier'])
        if self.args.security:
            for sg in self['VpcSecurityGroups']:
                self.connect(fh, self.name, sg['VpcSecurityGroupId'])


###############################################################################
def elbcmd(cmd):
    return awscmd(cmd, 'elb')


###############################################################################
def rdscmd(cmd):
    return awscmd(cmd, 'rds')


###############################################################################
def ec2cmd(cmd):
    return awscmd(cmd, 'ec2')


###############################################################################
def awscmd(cmd, area='ec2'):
    cachepath = '.cache'
    if not os.path.exists(cachepath):
        os.mkdir(cachepath)
    fullcmd = 'aws %s %s %s' % (" ".join(awsflags), area, cmd)
    cachefile = os.path.join(cachepath, md5.md5(fullcmd).hexdigest())

    if not nocache and os.path.exists(cachefile):
        with open(cachefile) as f:
            data = f.read()
    else:
        with os.popen(fullcmd) as f:
            data = f.read()
            with open(cachefile, 'w') as g:
                g.write(data)

    try:
        return json.loads(data)
    except ValueError:
        sys.stderr.write("Failed to decode output from %s\n%s\n" % (fullcmd, data))
        sys.exit(1)


###############################################################################
def get_all_internet_gateways(args):
    if args.verbose:
        sys.stderr.write("Getting internet gateways\n")
    igw_data = ec2cmd("describe-internet-gateways")['InternetGateways']
    for igw in igw_data:
        g = InternetGateway(igw, args)
        objects[g.name] = g


###############################################################################
def get_vpc_list(args):
    vpc_data = ec2cmd("describe-vpcs")['Vpcs']
    for vpc in vpc_data:
        if args.vpc and vpc['VpcId'] != args.vpc:
            continue
        if args.verbose:
            sys.stderr.write("VPC: %s\n" % vpc['VpcId'])
        g = VPC(vpc, args)
        objects[g.name] = g


###############################################################################
def get_all_instances(args):
    if args.verbose:
        sys.stderr.write("Getting instances\n")
    reservation_list = ec2cmd("describe-instances")['Reservations']
    for reservation in reservation_list:
        for instance in reservation['Instances']:
            i = Instance(instance, args)
            objects[i.name] = i


###############################################################################
def get_all_subnets(args):
    if args.verbose:
        sys.stderr.write("Getting subnets\n")
    subnets = ec2cmd("describe-subnets")['Subnets']
    for subnet in subnets:
        if args.subnet and subnet['SubnetId'] != args.subnet:
            pass
        elif args.verbose:
            sys.stderr.write("Subnet: %s\n" % subnet['SubnetId'])
        s = Subnet(subnet, args)
        objects[s.name] = s


###############################################################################
def get_all_volumes(args):
    if args.verbose:
        sys.stderr.write("Getting volumes\n")
    volumes = ec2cmd("describe-volumes")['Volumes']
    for volume in volumes:
        v = Volume(volume, args)
        objects[v.name] = v


###############################################################################
def get_all_security_groups(args):
    if args.verbose:
        sys.stderr.write("Getting security groups\n")
    sgs = ec2cmd("describe-security-groups")['SecurityGroups']
    for sg in sgs:
        s = SecurityGroup(sg, args)
        objects[s.name] = s


###############################################################################
def get_all_route_tables(args):
    if args.verbose:
        sys.stderr.write("Getting route tables\n")
    rts = ec2cmd('describe-route-tables')['RouteTables']
    for rt in rts:
        r = RouteTable(rt, args)
        objects[r.name] = r


###############################################################################
def get_all_network_interfaces(args):
    if args.verbose:
        sys.stderr.write("Getting NICs\n")
    nics = ec2cmd('describe-network-interfaces')['NetworkInterfaces']
    for nic in nics:
        n = NetworkInterface(nic, args)
        objects[n.name] = n


###############################################################################
def get_all_rds(args):
    if args.verbose:
        sys.stderr.write("Getting Databases\n")
    dbs = rdscmd('describe-db-instances')['DBInstances']
    for db in dbs:
        rds = Database(db, args)
        objects[rds.name] = rds


###############################################################################
def get_all_elbs(args):
    if args.verbose:
        sys.stderr.write("Getting Load Balancers\n")
    elbs = elbcmd('describe-load-balancers')['LoadBalancerDescriptions']
    for elb in elbs:
        lb = LoadBalancer(elb, args)
        objects[lb.name] = lb


###############################################################################
def map_region(args):
    # EC2
    get_vpc_list(args)
    get_all_internet_gateways(args)
    get_all_network_interfaces(args)
    get_all_instances(args)
    get_all_subnets(args)
    get_all_volumes(args)
    get_all_route_tables(args)
    if args.security:
        get_all_security_groups(args)

    # RDS
    get_all_rds(args)

    # ELB
    get_all_elbs(args)


###############################################################################
def parseArgs():
    global nocache
    global awsflags
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--awsflag', default=None, help="Flags to pass to aws calls [None]")
    parser.add_argument(
        '--vpc', default=None, help="Which VPC to examine [all]")
    parser.add_argument(
        '--subnet', default=None, help="Which subnet to examine [all]")
    parser.add_argument(
        '--iterate', default=None, choices=['vpc', 'subnet'],
        help="Create different maps for each vpc or subnet")
    parser.add_argument(
        '--nocache', default=False, action='store_true',
        help="Don't read from cache'd data")
    parser.add_argument(
        '--output', default=sys.stdout, type=argparse.FileType('w'),
        help="Which file to output to [stdout]")
    parser.add_argument(
        '--security', default=False, action='store_true',
        help="Draw in security groups")
    parser.add_argument(
        '-v', '--verbose', default=False, action='store_true',
        help="Print some details")
    args = parser.parse_args()
    nocache = args.nocache
    if args.vpc and not args.vpc.startswith('vpc-'):
        args.vpc = "vpc-%s" % args.vpc
    if args.subnet and not args.subnet.startswith('subnet-'):
        args.subnet = "subnet-%s" % args.subnet
    if args.awsflag:
        awsflags = ["--%s" % args.awsflag]
    return args


###############################################################################
def generate_map(fh):
    fh.write("digraph G {\n")
    fh.write('overlap=false\n')
    fh.write('ranksep=1.6\n')

    # Draw all the objects
    for obj in sorted(objects.values()):
        obj.draw(fh)

    # Assign Ranks
    for objtype in [Database, LoadBalancer, Subnet, Instance, VPC, InternetGateway, RouteTable]:
        fh.write('// Rank %s\n' % objtype.__name__)
        fh.write('rank_%s [style=invisible]\n' % objtype.__name__)
        fh.write('{ rank=same; rank_%s; ' % objtype.__name__)
        for obj in sorted(objects.values()):
            if obj.__class__ == objtype:
                obj.rank(fh)
        fh.write('}\n')
    ranks = ['RouteTable', 'Subnet', 'Database', 'LoadBalancer', 'Instance', 'VPC', 'InternetGateway']
    strout = " -> ".join(["rank_%s" % x for x in ranks])
    fh.write("%s [style=invis];\n" % strout)

    fh.write("}\n")


###############################################################################
def main():
    args = parseArgs()
    map_region(args)
    if args.iterate:
        for o in objects.keys():
            if o.startswith(args.iterate):
                f = open('%s.dot' % o, 'w')
                setattr(args, args.iterate, o)
                generate_map(f)
                f.close()
    else:
        generate_map(args.output)

###############################################################################
if __name__ == '__main__':
    main()

#EOF
