# SeedLabVPNLab
SeedLabVPNLab
首先启动docker，10.0.2.6 10.0.2.7是客户端，10.0.2.8是连接局域网的路由器，局域网中有两个主机192.168.60.101 192.168.60.102

其次完成证书的生成，以及本地DNS配置
接下来
客户端：
./vpnclient seed dees 虚拟网卡声称的ip，每个客户端不一样的ip
服务端
./vpnserver 

从客户端可以访问到局域网
