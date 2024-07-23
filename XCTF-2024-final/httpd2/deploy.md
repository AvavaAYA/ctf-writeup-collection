1. 
```bash
docker build -t "httpd2" .
```

2. 
```bash
docker run -d -p "0.0.0.0:pub_port1:80" -p "0.0.0.0:pub_port2:8888" -h "httpd2" --name="httpd2" httpd2 
```

`pub_port1` and `pub_port2` Replace with the port you want to open to players。



**80端口 是web服务，8888端口是给选手反弹shell用。**
