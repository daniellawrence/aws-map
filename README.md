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

Iterating
---------
You can generate a map of each vpc or subnet individually. This is very useful if you have a large and complex setup where putting it all on a single page becomes spaghetti.
```
$ ./mapall.py --iterate vpc
$ ./mapall.py --iterave subnet
```


Cacheing
--------
The program will write the results of the aws query to a .cache
directory and use that unless you specify --nocache. Cacheing is
much faster than querying AWS everytime but obviously won't react
to changes that are made.
