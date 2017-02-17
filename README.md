aws-map
------------
Generate basic graphviz/dot maps of your AWS deployments.

installation
------------
```
$ pip install -r requirements.txt
$ sudo apt-get install graphviz
```

running
-------

```
$ ./mapall.py --region us-east-1 | dot -Tpng > aws-map.png
$ eog aws-map.png
```

Options include specifying just one VPC to draw with:
./mapall.py --vpc vpc_123456

Or specifying a subnet to draw with:
./mapall.py --subnet subnet_123456

If you want to use [virtualenv](http://docs.python-guide.org/en/latest/dev/virtualenvs/):

```
$ sudo apt-get install -y python-setuptools
$ virtualenv -p /usr/bin/python2.7 venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ ./mapall.py --region us-east-1 | dot -Tpng > aws-map.png

# And to leave the virtual environment:
$ deactivate
```

Iterating
---------
You can generate a map of each vpc or subnet individually. This is
very useful if you have a large and complex setup where putting it
all on a single page becomes spaghetti.

```
$ ./mapall.py --iterate vpc
$ ./mapall.py --iterate subnet
```

Security Groups
---------------
Normally security groups get in the way and obscure what you want
to see so they aren't included. You can add them back with --security.
Note that if you only want to map a single subnet you shouldn't
turn security groups on as there is no easy way to determine which
subnet a security group operates on - so it draws them all - leading
to potentially huge, unusable maps.

Cacheing
--------
The program will write the results of the aws query to a .cache
directory and use that unless you specify --nocache. Cacheing is
much faster than querying AWS everytime but obviously won't react
to changes that are made.
