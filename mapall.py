#!/usr/bin/env python
#
# Map AWS setup
# Images are available from http://aws.amazon.com/architecture/icons/
import argparse
import time
import os
import sys
import boto
import netaddr

objects = {}
clusternum = 0
awsflags = []
nocache = False
secGrpToDraw = set()

colours = ['azure', 'coral', 'wheat', 'deepskyblue', 'firebrick', 'gold', 'green', 'plum', 'salmon', 'sienna']


class RetryLimitExceeded(Exception):
    def __init__(self, exception, retries):
        self.exception = exception
        self.tries = retries

    def __str__(self):
        return repr(
            "Throttling retry limit exceeded, no_of_tries(%s), last exception: %s" % (self.tries, self.exception))


def get_api_error_code(exception):
    if hasattr(exception, "body"):
        if exception.body is not None and hasattr(exception.body, "split"):
            code = exception.body.split("<Code>")[1]
            code = code.split("</Code>")[0]
            return code
        else:
            return ""
    else:
        return ""


def paginate_boto_response(api_call, *args, **kwargs):
    resultset = []
    tries = 0
    retry_interval = 2
    retry = 10
    while True:

        tries += 1
        try:
            results = api_call(*args, **kwargs)
            if results:
                resultset += results
                if results.next_token:
                    kwargs['next_token'] = results.next_token
                else:
                    break
            else:
                break
        except Exception, e:
            last_exception = e
            code = get_api_error_code(e)
            if retry <= 0:
                raise RetryLimitExceeded(last_exception, tries)
            elif retry > 0 and (code == "Throttling" or code == "RequestLimitExceeded"):
                retry -= 1
                retry_interval += 1
                time.sleep(retry_interval)
            else:
                raise e

    return resultset

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
    def drawSec(self, fh):
        sys.stderr.write("%s.drawSec() undefined\n" % self.__class__.__name__)

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
    def inVpc(self, vpc):
        return False

    ##########################################################################
    def relevent_to_ip(self, ip):
        return False

    ##########################################################################
    def rank(self, fh):
        fh.write(self.mn())

    ##########################################################################
    def image(self, names=[]):
        if not names:
            names = [self.__class__.__name__]

        for name in names:
            imgfile = os.path.join(os.path.realpath(os.path.dirname(__file__)), 'images', '%s.png' % name)

            if os.path.exists(imgfile):
                imagestr = ', image="%s", shape=box ' % imgfile
                break
        else:
            imagestr = ', shape=box'
        return imagestr


###############################################################################
###############################################################################
###############################################################################
class NetworkAcl(Dot):
    """
    {
        "Associations": [
            {
            "SubnetId": "subnet-XXXXXXXX",
            "NetworkAclId": "acl-XXXXXXXX",
            "NetworkAclAssociationId": "aclassoc-XXXXXXXX"
            },
        ],
        "NetworkAclId": "acl-XXXXXXXX",
        "VpcId": "vpc-XXXXXXXX",
        "Tags": [],
        "Entries": [ {
            "CidrBlock": "0.0.0.0/0",
            "RuleNumber": 1,
            "Protocol": "-1",
            "Egress": true,
            "RuleAction": "allow"
            }, ],
        "IsDefault": true
    }
    """

    def __init__(self, instance, args):
        self.data = instance
        self.name = instance.id
        self.args = args

    def inVpc(self, vpc):
        if vpc and self.data.vpc_id != vpc:
            return False
        return True

    def inSubnet(self, subnet=None):
        if subnet:
            for assoc in self['Associations']:
                if assoc['SubnetId'] == subnet:
                    return True
            return False
        return True

    def draw(self, fh):
        fh.write("// NACL %s\n" % self.name)

    def drawSec(self, fh):
        fh.write("// NACL %s\n" % self.name)
        fh.write('%s [shape="box", label="%s"];\n' % (self.mn(), self.name))
        self.genRuleBlock('ingress', fh)
        fh.write("%s -> %s_ingress_rules\n" % (self.mn(), self.mn()))
        self.genRuleBlock('egress', fh)
        fh.write("%s_egress_rules -> %s\n" % (self.mn(), self.mn()))

    def genRuleBlock(self, direct, fh):
        fh.write("// NACL %s\n" % self.name)
        fh.write('%s_%s_rules [ shape="Mrecord" label=<<table border="1">' % (self.mn(), direct))
        fh.write('<tr><td colspan="3">%s %s</td></tr>\n' % (self.name, direct))
        fh.write('<tr>%s %s %s</tr>\n' % (header("Rule"), header("CIDR"), header("Ports")))
        for e in self['Entries']:
            if direct == 'ingress' and e['Egress']:
                continue
            if direct == 'egress' and not e['Egress']:
                continue
            col = "green" if e['RuleAction'] == 'allow' else "red"
            protocol = {'6': 'tcp', '17': 'udp'}.get(e['Protocol'], e['Protocol'])
            if 'PortRange' in e:
                if e['PortRange']['From'] == e['PortRange']['To']:
                    portrange = "%s/%s" % (e['PortRange']['From'], protocol)
                else:
                    portrange = "%s-%s/%s" % (e['PortRange']['From'], e['PortRange']['To'], protocol)
            else:
                portrange = ''
            fh.write("<tr>\n")
            fh.write('<td bgcolor="%s">%s</td>' % (col, e['RuleNumber']))
            fh.write("<td>%s</td>" % e['CidrBlock'])
            fh.write("<td>%s</td>\n" % portrange)
            fh.write("</tr>\n")
        fh.write("</table>>\n")
        fh.write("];\n")

    def relevent_to_ip(self, ip):
        for e in self['Entries']:
            if netaddr.IPAddress(ip) in netaddr.IPNetwork(e['CidrBlock']):
                print "NACL %s - ip %s is relevent to %s" % (self.name, ip, e['CidrBlock'])
                return True
        return False


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
        self.name = instance.id
        self.args = args

    def inSubnet(self, subnet=None):
        if subnet and self['SubnetId'] != subnet:
            return False
        return True

    def inVpc(self, vpc=None):
        if vpc and self.data.vpc_id != vpc:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def drawSec(self, fh):
        fh.write('// Instance %s\n' % self.name)
        label = "%s\\n%s\\n%s" % (self.tags('Name'), self.name, self['PrivateIpAddress'])
        fh.write('%s [label="%s" %s];\n' % (self.mn(self.name), label, self.image()))
        for sg in self['SecurityGroups']:
            self.connect(fh, self.name, sg['GroupId'])
        if self['SubnetId']:
            self.connect(fh, self.name, self['SubnetId'])

    def draw(self, fh):
        global clusternum
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        fh.write('// Instance %s\n' % self.name)
        fh.write('subgraph cluster_%d {\n' % clusternum)
        if 'Name' in self.data.tags:
            label = self.data.tags['Name']
        else:
            label = self.name
        fh.write('%s [label="%s" %s];\n' % (self.mn(self.name), label, self.image()))

        extraconns = []
        for o in objects.values():
            if o.partOfInstance(self.name):
                self.connect(fh, self.name, o.name)
                extraconns = o.subclusterDraw(fh)
        fh.write('graph [style=dotted]\n')
        fh.write('}\n')  # End subgraph cluster
        if self.data.subnet_id:
            self.connect(fh, self.name, self.data.subnet_id)
        for ic, ec in extraconns:
            self.connect(fh, ic, ec)
        clusternum += 1
        if self.args.security:
            for sg in self.data.groups:
                self.connect(fh, self.name, sg.id)


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
        self.name = subnet.id
        self.args = args

    def inVpc(self, vpc):
        if vpc and self.data.vpc_id != vpc:
            return False
        return True

    def relevent_to_ip(self, ip):
        if netaddr.IPAddress(ip) in netaddr.IPNetwork(self.data.cidr_block):
            print "Subnet %s - ip %s is relevent to %s" % (self.name, ip, self.data.cidr_block)
            return True
        return False

    def inSubnet(self, subnet=None):
        if subnet and self['SubnetId'] != subnet:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def drawSec(self, fh):
        fh.write('// Subnet %s\n' % self.name)
        fh.write('%s [label="%s\\n%s" %s];\n' % (self.mn(self.name), self.name, self.data.cidr_block, self.image()))
        self.connect(fh, self.name, self.data.vpc_id)

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        if 'Name' in self.data.tags:
            label = self.data.tags['Name']
        else:
            label = self.name

        fh.write('// Subnet %s\n' % self.name)
        fh.write('%s [label="%s\\n%s" %s];\n' % (self.mn(self.name), label, self.data.cidr_block, self.image()))
        self.connect(fh, self.name, self.data.vpc_id)


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

    def drawSec(self, fh):
        return

    def draw(self, fh):
        if self['State'] not in ('in-use',):
            if self.args.vpc:
                return
            if self.args.subnet or self.args.vpc:
                return
            fh.write('%s [label="Unattached Volume:%s\\n%s Gb" %s];\n' % (
                self.mn(self.name), self.name, self['Size'], self.image()))

    def subclusterDraw(self, fh):
        fh.write('%s [shape=box, label="%s\\n%s Gb"];\n' % (self.mn(self.name), self.name, self['Size']))
        return []


###############################################################################
###############################################################################
###############################################################################
class SecurityGroup(Dot):
    """
    u'Description': u'SG Description',
    u'GroupId': u'sg-XXXXXXXX'
    u'GroupName': u'XXX_GroupName_XXX',
    u'IpPermissions': [
        {u'ToPort': 443, u'IpProtocol': u'tcp',
        u'IpRanges': [{u'CidrIp': u'0.0.0.0/0'}],
        u'UserIdGroupPairs': [], u'FromPort': 443}],
    u'IpPermissionsEgress': [
        {u'ToPort': 4502, u'IpProtocol': u'tcp',
        u'IpRanges': [{u'CidrIp': u'0.0.0.0/0'}],
        u'UserIdGroupPairs': [], u'FromPort': 4502}],
    u'OwnerId': u'XXXXXXXXXXXX',
    u'Tags': [{u'Key': u'Key', u'Value': u'Value'}, ...
    u'VpcId': u'vpc-XXXXXXXX',
    """

    def __init__(self, sg, args):
        self.data = sg
        self.name = sg.id
        self.args = args
        self.drawn = False

    def draw(self, fh):
        if self.args.vpc and self.data.vpc_id != self.args.vpc:
            return

        portstr = self.permstring(fh, self.data.rules)
        eportstr = self.permstring(fh, self.data.rules_egress)

        tportstr = []
        if portstr:
            tportstr.append("Ingress: %s" % portstr)
        if eportstr:
            tportstr.append("Egress: %s" % eportstr)
        desc = "\\n".join(chunkstring(self.data.description, 20))
        fh.write('%s [label="SG: %s\\n%s\\n%s" %s];\n' % (
            self.mn(self.name), self.name, desc, "\\n".join(tportstr), self.image()))

    def drawSec(self, fh):
        global clusternum
        self.extraRules = []
        fh.write("// SG %s\n" % self.name)
        fh.write('subgraph cluster_%d {\n' % clusternum)
        fh.write('style=filled; color="grey90";\n')
        fh.write('node [style=filled, color="%s"];\n' % colours[clusternum])
        desc = "\\n".join(chunkstring(self['Description'], 20))
        fh.write('%s [shape="rect", label="%s\\n%s"]\n' % (self.mn(), self.name, desc))
        if self['IpPermissions']:
            self.genRuleBlock(self['IpPermissions'], 'ingress', fh)
        if self['IpPermissionsEgress']:
            self.genRuleBlock(self['IpPermissionsEgress'], 'egress', fh)
        clusternum += 1
        fh.write("}\n")

        if self['IpPermissions']:
            fh.write("%s_ingress_rules -> %s [weight=5];\n" % (self.mn(), self.mn()))
        if self['IpPermissionsEgress']:
            fh.write("%s -> %s_egress_rules [weight=5];\n" % (self.mn(), self.mn()))
        for r in self.extraRules:
            fh.write(r)
        self.drawn = True

    def genRuleBlock(self, struct, direct, fh):
        fh.write("// SG %s %s\n" % (self.name, direct))
        for e in struct:
            fh.write("// %s\n" % e)
        fh.write('%s_%s_rules [ shape="Mrecord" label=<<table border="1">' % (self.mn(), direct))
        fh.write('<tr><td colspan="2"><b>%s %s</b></td></tr>\n' % (self.name, direct))
        fh.write('<tr>%s %s</tr>\n' % (header('CIDR'), header('Ports')))

        for e in struct:
            fh.write("<tr>\n")
            ipranges = []
            for ipr in e['IpRanges']:
                if 'CidrIp' in ipr:
                    ipranges.append(ipr['CidrIp'])

            if ipranges:
                if len(ipranges) > 1:
                    iprangestr = "<table>"
                    for ipr in ipranges:
                        iprangestr += "<tr><td>%s</td></tr>" % ipr
                    iprangestr += "</table>"
                else:
                    iprangestr = "%s" % ipranges[0]
            else:
                iprangestr = "See %s" % e['UserIdGroupPairs'][0]['GroupId']
            fh.write("<td>%s</td>" % iprangestr)
            if 'FromPort' in e and e['FromPort']:
                fh.write("<td>%s - %s/%s</td>" % (e['FromPort'], e['ToPort'], e['IpProtocol']))
            else:
                fh.write("<td>ALL</td>\n")
            fh.write("</tr>\n")
        fh.write("</table>>\n")
        fh.write("];\n")

        for e in struct:
            if e['UserIdGroupPairs']:
                for pair in e['UserIdGroupPairs']:
                    secGrpToDraw.add(pair['GroupId'])
                    self.extraRules.append('%s_%s_rules -> %s;\n' % (self.mn(), direct, self.mn(pair['GroupId'])))

    def relevent_to_ip(self, ip):
        for i in self['IpPermissions']:
            for ipr in i['IpRanges']:
                if netaddr.IPAddress(ip) in netaddr.IPNetwork(ipr['CidrIp']):
                    return True
        for i in self['IpPermissionsEgress']:
            for ipr in i['IpRanges']:
                if netaddr.IPAddress(ip) in netaddr.IPNetwork(ipr['CidrIp']):
                    return True
        return False

    def permstring(self, fh, obj):
        """
        Convert the permutations and combinations into a sensible output
        """
        ans = []
        if not obj:
            return ''
        for ip in obj:
            if ip.grants.__len__ > 0:
                for pair in ip.grants:
                    self.connect(fh, self.name, pair.group_id)
            if ip.from_port is not None:
                ipranges = []
                for ipr in ip.grants:
                    if ipr.cidr_ip is not None:
                        ipranges.append(ipr.cidr_ip)
                iprangestr = ';'.join(ipranges)
                ans.append("%s %s->%s/%s" % (iprangestr, ip.from_port, ip.to_port, ip.ip_protocol))
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
        self.name = vpc.id
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

    def relevent_to_ip(self, ip):
        if netaddr.IPAddress(ip) in netaddr.IPNetwork(self.data.cidr_block):
            print "VPC %s - ip %s is relevent to %s" % (self.name, ip, self.data.cidr_block)
            return True
        return False

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def drawSec(self, fh):
        fh.write('%s [label="%s:%s" %s];\n' % (self.mn(self.name), self.__class__.__name__, self.name, self.image()))

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
        self.name = rt.id

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def inVpc(self, vpc):
        if vpc and self.data.vpc_id != vpc:
            return False
        return True

    def relevent_to_ip(self, ip):
        for rt in self['Routes']:
            if netaddr.IPAddress(ip) in netaddr.IPNetwork(rt['DestinationCidrBlock']):
                print "RT %s - ip %s is relevent to %s" % (self.name, ip, rt['DestinationCidrBlock'])
                return True
        return False

    def inSubnet(self, subnet):
        if not subnet:
            return True
        for a in self['Associations']:
            if subnet == a.get('SubnetId', None):
                return True
        return False

    def drawSec(self, fh):
        routelist = []
        for rt in self['Routes']:
            if 'DestinationCidrBlock' in rt:
                routelist.append(rt['DestinationCidrBlock'])
        fh.write('%s [ shape="Mrecord" label=<<table border="1">' % self.mn())
        fh.write('<tr><td colspan="2">%s</td></tr>\n' % self.name)
        fh.write('<tr>%s %s</tr>\n' % (header('Source'), header('Dest')))
        for route in self['Routes']:
            colour = 'green'
            if route['State'] != 'active':
                colour = 'red'
            if 'GatewayId' in route:
                src = route['GatewayId']
            else:
                src = route['InstanceId']
            fh.write('<tr color="%s"><td>%s</td><td>%s</td></tr>\n' % (colour, src, route['DestinationCidrBlock']))
        fh.write("</table>>];\n")

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        routelist = []
        for rt in self.data.routes:
            if rt.destination_cidr_block is not None:
                routelist.append(rt.destination_cidr_block)
        fh.write('%s [label="RT: %s\\n%s" %s];\n' % (self.mn(), self.name, ";".join(routelist), self.image()))
        for ass in self.data.associations:
            if ass.subnet_id is not None:
                if objects[ass.subnet_id].inSubnet(self.args.subnet):
                    self.connect(fh, self.name, ass.subnet_id)
        for rt in self.data.routes:
            if rt.instance_id is not None:
                if objects[rt.instance_id].inSubnet(self.args.subnet):
                    self.connect(fh, self.name, rt.instance_id)
            elif rt.interface_id is not None:
                self.connect(fh, self.name, rt.instance_id)


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
        self.name = nic.id

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
        fh.write(
            '%s [label="NIC: %s\\n%s" %s];\n' % (self.mn(self.name), self.name, self['PrivateIpAddress'], self.image()))
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
        self.name = igw.id
        self.conns = []
        for i in igw.attachments:
            # print(i)
            self.conns.append(i)
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
                self.connect(fh, self.name, i.vpc_id)


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
        self.name = lb.name
        self.args = args

    def inSubnet(self, subnet=None):
        if subnet and subnet not in self.data.subnets:
            return False
        return True

    def inVpc(self, vpc):
        if vpc and self.data.vpc_id != vpc:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        ports = []
        for l in self.data.listeners:
            # x = l['Listener']
            ports.append(
                "%s/%s -> %s/%s" % (l.load_balancer_port, l.protocol, l.instance_port, l.instance_protocol))

        fh.write('%s [label="ELB: %s\\n%s" %s];\n' % (self.mn(self.name), self.name, "\n".join(ports), self.image()))
        for i in self.data.instances:
            if objects[i.id].inSubnet(self.args.subnet):
                self.connect(fh, self.name, i.id)
        for s in self.data.subnets:
            if self.args.subnet:
                if s != self.args.subnet:
                    continue
            self.connect(fh, self.name, s)
        if self.args.security:
            for sg in self.data.security_groups:
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
        self.name = db.id
        self.args = args

    def inSubnet(self, subnet=None):
        if not subnet:
            return True
        for snet in self['DBSubnetGroup']['Subnets']:
            if subnet == snet['SubnetIdentifier']:
                return True
        return False

    def inVpc(self, vpc):
        if vpc and self.data.subnet_group.vpc_id != vpc:
            return False
        return True

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def drawSec(self, fh):
        imgstr = self.image(["Database-%s" % self['Engine'], 'Database'])
        fh.write('%s [label="DB: %s\\n%s" %s];\n' % (self.mn(self.name), self.name, self['Engine'], imgstr))

    def draw(self, fh):
        if not self.inVpc(self.args.vpc) or not self.inSubnet(self.args.subnet):
            return
        fh.write('// Database %s\n' % self.name)
        imgstr = self.image(["Database-%s" % self.data.engine, 'Database'])
        fh.write('%s [label="DB: %s\\n%s" %s];\n' % (self.mn(self.name), self.name, self.data.engine, imgstr))
        for subnet in self.data.subnet_group.subnet_ids:
            # if subnet.SubnetStatus == 'Active':
                if objects[subnet].inSubnet(self.args.subnet):
                    self.connect(fh, self.name, subnet)
        if self.args.security:
            for sg in self.data.vpc_security_groups:
                self.connect(fh, self.name, sg.vpc_group)


class ASG(Dot):
    def __init__(self, db, args):
        self.data = db
        self.name = db.name
        self.args = args

    """
    {
    "AutoScalingGroups": [
       {
          "AutoScalingGroupARN": "arn:aws:autoscaling:us-west-2:803981987763:autoScalingGroup:930d940e-891e-4781-a11a-7b0acd480f03:autoScalingGroupName/my-test-asg",
          "HealthCheckGracePeriod": 0,
          "SuspendedProcesses": [],
          "DesiredCapacity": 1,
          "Tags": [],
          "EnabledMetrics": [],
          "LoadBalancerNames": [],
          "AutoScalingGroupName": "my-test-asg",
          "DefaultCooldown": 300,
          "MinSize": 0,
          "Instances": [
              {
                  "InstanceId": "i-4ba0837f",
                  "AvailabilityZone": "us-west-2c",
                  "HealthStatus": "Healthy",
                  "LifecycleState": "InService",
                  "LaunchConfigurationName": "my-test-lc"
               }
           ],
           "MaxSize": 1,
           "VPCZoneIdentifier": null,
           "TerminationPolicies": [
                 "Default"
           ],
           "LaunchConfigurationName": "my-test-lc",
           "CreatedTime": "2013-08-19T20:53:25.584Z",
           "AvailabilityZones": [
               "us-west-2c"
           ],
           "HealthCheckType": "EC2"
       }
    ]
}

    """

    def image(self, names=[]):
        return super(ASG, self).image(names)

    def draw(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write('// ASG %s\n' % self.name)
            imgstr = self.image(["ASG-%s" % self.data.name, 'ASG'])
            fh.write('%s [label="ASG: %s\\n%s" %s];\n' % (self.mn(self.name), self.name, '', imgstr))
            for lb in self.data.load_balancers:
                if objects[lb].inSubnet(self.args.subnet):
                    self.connect(fh, self.name, lb)

    def rank(self, fh):
        if self.inVpc(self.args.vpc) and self.inSubnet(self.args.subnet):
            fh.write("%s;" % self.mn())

    def inVpc(self, vpc):
        if vpc:
            subnets = self.data.vpc_zone_identifier
            for subnet in subnets.split(','):
                # sys.stderr.write(subnet)
                if vpc and subnet in objects and objects[subnet].data.vpc_id == vpc:
                    return True
            return False
        return True


###############################################################################

def header(lbl):
    return '<td bgcolor="black"><font color="white">%s</font></td>' % lbl


###############################################################################
def chunkstring(strng, length):
    """ Break a string on word boundaries, where each line is up to
    length characters long """
    ans = []
    line = []
    for w in strng.split():
        if len(w) >= length:
            ans.append(" ".join(line))
            ans.append(w)
            line = []
            continue
        if len(" ".join(line)) + len(w) < length:
            line.append(w)
        else:
            ans.append(" ".join(line))
            line = []
    ans.append(" ".join(line))
    return ans

###############################################################################
def get_all_internet_gateways(args):
    if args.verbose:
        sys.stderr.write("Getting internet gateways\n")
    # igw_data = ec2cmd("describe-internet-gateways")['InternetGateways']
    import boto.vpc
    igw_data = paginate_boto_response(boto.vpc.connect_to_region(args.region).get_all_internet_gateways)
    for igw in igw_data:
        g = InternetGateway(igw, args)
        objects[g.name] = g


###############################################################################
def get_vpc_list(args):
    import boto.vpc
    vpc_data = paginate_boto_response(boto.vpc.connect_to_region(args.region).get_all_vpcs)
    # vpc_data = ec2cmd("describe-vpcs")['Vpcs']
    for vpc in vpc_data:
        if args.vpc and vpc.id != args.vpc:
            continue
        if args.verbose:
            sys.stderr.write("VPC: %s\n" % vpc.id)
        g = VPC(vpc, args)
        objects[g.name] = g


###############################################################################
def get_all_instances(args):
    if args.verbose:
        sys.stderr.write("Getting instances\n")
    import boto.ec2
    reservation_list = paginate_boto_response(boto.ec2.connect_to_region(args.region).get_all_reservations)
    # reservation_list = ec2cmd("describe-instances")['Reservations']
    for reservation in reservation_list:
        for instance in reservation.instances:
            i = Instance(instance, args)
            objects[i.name] = i
            if args.verbose:
                sys.stderr.write("Instance: %s\n" % i.name)


###############################################################################
def get_all_subnets(args):
    if args.verbose:
        sys.stderr.write("Getting subnets\n")
    import boto.vpc
    subnets = paginate_boto_response(boto.vpc.connect_to_region(args.region).get_all_subnets)
    for subnet in subnets:
        if args.subnet and subnet.id != args.subnet:
            pass
        elif args.verbose:
            sys.stderr.write("Subnet: %s\n" % subnet.id)
        s = Subnet(subnet, args)
        objects[s.name] = s


###############################################################################
def get_all_volumes(args):
    if args.verbose:
        sys.stderr.write("Getting volumes\n")
    # volumes = ec2cmd("describe-volumes")['Volumes']
    volumes = paginate_boto_response(boto.ec2.connect_to_region(args.region).get_all_volumes)
    for volume in volumes:
        v = Volume(volume, args)
        objects[v.name] = v


###############################################################################
def get_all_security_groups(args):
    if args.verbose:
        sys.stderr.write("Getting security groups\n")
    import boto.ec2
    sgs = paginate_boto_response(boto.ec2.connect_to_region(args.region).get_all_security_groups)
    # sgs = ec2cmd("describe-security-groups")['SecurityGroups']
    for sg in sgs:
        s = SecurityGroup(sg, args)
        objects[s.name] = s
        if args.verbose:
            sys.stderr.write("SG %s\n" % s.name)


###############################################################################
def get_all_route_tables(args):
    if args.verbose:
        sys.stderr.write("Getting route tables\n")
    # rts = ec2cmd('describe-route-tables')['RouteTables']
    import boto.vpc
    rts = paginate_boto_response(boto.vpc.connect_to_region(args.region).get_all_route_tables)
    for rt in rts:
        r = RouteTable(rt, args)
        objects[r.name] = r


###############################################################################
def get_all_network_interfaces(args):
    if args.verbose:
        sys.stderr.write("Getting NICs\n")
    import boto.ec2
    nics = paginate_boto_response(boto.ec2.connect_to_region(args.region).get_all_network_interfaces)
    # nics = ec2cmd('describe-network-interfaces')['NetworkInterfaces']
    for nic in nics:
        n = NetworkInterface(nic, args)
        objects[n.name] = n


###############################################################################
def get_all_rds(args):
    if args.verbose:
        sys.stderr.write("Getting Databases\n")
    import boto.rds
    dbs = paginate_boto_response(boto.rds.connect_to_region(args.region).get_all_dbinstances)
    # dbs = rdscmd('describe-db-instances')['DBInstances']
    for db in dbs:
        rds = Database(db, args)
        objects[rds.name] = rds
        if args.verbose:
            sys.stderr.write("RDS: %s\n" % rds.name)


###############################################################################
def get_all_elbs(args):
    if args.verbose:
        sys.stderr.write("Getting Load Balancers\n")
    import boto.ec2.elb
    elbs = paginate_boto_response(boto.ec2.elb.connect_to_region(args.region).get_all_load_balancers)
    # elbs = elbcmd('describe-load-balancers')['LoadBalancerDescriptions']
    for elb in elbs:
        lb = LoadBalancer(elb, args)
        if args.verbose:
            sys.stderr.write("ELBs: %s\n" % lb.name)
        objects[lb.name] = lb


###############################################################################
def get_all_networkacls(args):
    if args.verbose:
        sys.stderr.write("Getting NACLs\n")
    import boto.vpc
    nacls = paginate_boto_response(boto.vpc.connect_to_region(args.region).get_all_network_acls)
    # nacls = ec2cmd('describe-network-acls')['NetworkAcls']
    for nacl in nacls:
        nc = NetworkAcl(nacl, args)
        objects[nc.name] = nc
        if args.verbose:
            sys.stderr.write("NACL: %s\n" % nc.name)


###############################################################################
def get_all_asgs(args):
    if args.verbose:
        sys.stderr.write("Getting ASGs\n")
    # asgs = asgcmd('describe-auto-scaling-groups')['AutoScalingGroups']
    import boto.ec2.autoscale
    asgs = paginate_boto_response(boto.ec2.autoscale.connect_to_region(args.region).get_all_groups)
    for asg in asgs:
        _asg = ASG(asg, args)
        objects[_asg.name] = _asg
        if args.verbose:
            sys.stderr.write("ASGs: %s\n" % _asg.name)


def map_region(args):
    # EC2
    get_vpc_list(args)
    get_all_internet_gateways(args)
    get_all_network_interfaces(args)
    get_all_instances(args)
    get_all_subnets(args)
    if args.volumes:
        get_all_volumes(args)
    get_all_route_tables(args)
    get_all_security_groups(args)
    get_all_networkacls(args)

    # RDS
    get_all_rds(args)

    # ELB
    get_all_elbs(args)

    get_all_asgs(args)


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
        '--secmap', default=None,
        help="Draw a security map for specified ec2")
    parser.add_argument(
        '--volumes', default=False,
        help="enables volumes")
    parser.add_argument(
        '-v', '--verbose', default=False, action='store_true',
        help="Print some details")

    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument(
        '--region', default=None, required=True,
        help="ec2 region")

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
def generateHeader(fh):
    fh.write("digraph G {\n")
    fh.write('overlap=false\n')
    fh.write('ranksep=1.6\n')
    fh.write('splines=ortho\n')


###############################################################################
def generateFooter(fh):
    fh.write("}\n")


###############################################################################
def generate_secmap(ec2, fh):
    """ Generate a security map instead """
    generateHeader(fh)
    subnet = objects[ec2]['SubnetId']
    vpc = objects[ec2]['VpcId']

    # The ec2
    objects[ec2].drawSec(fh)

    # Security groups associated with the ec2
    for sg in objects[ec2]['SecurityGroups']:
        secGrpToDraw.add(sg['GroupId'])
        objects[sg['GroupId']].drawSec(fh)

    # Subnet ec2 is on
    subnet = objects[ec2]['SubnetId']
    objects[subnet].drawSec(fh)

    # NACLs and RTs associated with that subnet
    for obj in objects.values():
        if obj.__class__ in (NetworkAcl, RouteTable):
            for assoc in obj['Associations']:
                if 'SubnetId' in assoc and assoc['SubnetId'] == subnet:
                    obj.drawSec(fh)
                    fh.write("%s -> %s\n" % (obj.mn(), objects[subnet].mn()))
            continue
        if obj.__class__ in (Database, ):
            for sg in obj['VpcSecurityGroups']:
                if sg['VpcSecurityGroupId'] in secGrpToDraw:
                    obj.drawSec(fh)

    # VPC that the EC2 is in
    objects[vpc].drawSec(fh)

    # Finish any referred to SG
    for sg in list(secGrpToDraw):
        if not objects[sg].drawn:
            objects[sg].drawSec(fh)

    generateFooter(fh)


###############################################################################
def generate_map(fh, args):
    generateHeader(fh)

    # Draw all the objects
    for obj in sorted(objects.values()):
        if obj.__class__ == SecurityGroup:
            if not args.security:
                continue
        obj.draw(fh)

    # Assign Ranks
    for objtype in [Database, LoadBalancer, Subnet, Instance, VPC, InternetGateway, RouteTable, ASG]:
        fh.write('// Rank %s\n' % objtype.__name__)
        fh.write('rank_%s [style=invisible]\n' % objtype.__name__)
        fh.write('{ rank=same; rank_%s; ' % objtype.__name__)
        for obj in sorted(objects.values()):
            if obj.__class__ == objtype:
                obj.rank(fh)
        fh.write('}\n')
    ranks = ['RouteTable', 'Subnet', 'Database', 'LoadBalancer', 'ASG', 'Instance', 'VPC', 'InternetGateway']
    strout = " -> ".join(["rank_%s" % x for x in ranks])
    fh.write("%s [style=invis];\n" % strout)

    generateFooter(fh)


###############################################################################
def main():
    args = parseArgs()
    map_region(args)
    if args.secmap:
        generate_secmap(args.secmap, args.output)
        return
    if args.iterate:
        for o in objects.keys():
            if o.startswith(args.iterate):
                f = open('%s.dot' % o, 'w')
                setattr(args, args.iterate, o)
                generate_map(f, args)
                f.close()
    else:
        generate_map(args.output, args)

###############################################################################
if __name__ == '__main__':
    main()

# EOF
