#!/usr/bin/env python
import boto.ec2
import boto.vpc
from local_settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
import pprint

def region_connect(region_name):
   vpc_conn = boto.vpc.connect_to_region(region_name,
                                         aws_access_key_id=AWS_ACCESS_KEY_ID,
                                         aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
   ec2_conn = boto.ec2.connect_to_region(region_name,
                                         aws_access_key_id=AWS_ACCESS_KEY_ID,
                                         aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

   return vpc_conn

def get_all_routetables(vpc_conn, filters={}):
    raw_route_tables = vpc_conn.get_all_route_tables(filters=filters)
    for rt in raw_route_tables:
        #pprint.pprint(rt.__dict__)
        for a in rt.associations:
            if not a.subnet_id:
                continue
            pprint.pprint(a.__dict__)
        for r in rt.routes:
            gateway = r.gateway_id
            if r.instance_id:
                gateway = r.instance_id
            print "%-20s -> %s" % (r.destination_cidr_block, gateway)
        print "=="
   
def get_all_subnets(vpc_conn, filters={}):
    raw_subnet_list = vpc_conn.get_all_subnets()
    for s in raw_subnet_list:
        get_all_routetables(vpc_conn, filters={'vpc_id': s.vpc_id})
        #get_all_internet_gateways(vpc_conn)

def get_all_internet_gateways(vpc_conn, filters={}):
    raw_igw_list = vpc_conn.get_all_internet_gateways(filters=filters)
    for igw in raw_igw_list:
        print igw

def main():
    "Main"

    vpc_conn = region_connect('ap-southeast-2')
    get_all_subnets(vpc_conn)
    

if __name__ == '__main__':
    main()
