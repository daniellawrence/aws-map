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
$ ./mapall.py | dot -Tpng > aws-map.png
$ eog aws-map.png
```

Options include specifying just one VPC to draw with:
./mapall.py --vpc vpc_123456

Or specifying a subnet to draw with:
./mapall.py --subnet subnet_123456

Cacheing
--------
The program will write the results of the aws query to 
a .cache directory. But it will only use this if you
specify --cache. This is much faster than querying AWS
everytime but obviously won't react to changes that are
made.
