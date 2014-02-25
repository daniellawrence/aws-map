aws-map
------------
Generate a very basic graphviz/dot map of your AWS deployments.

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
