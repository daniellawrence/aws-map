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


