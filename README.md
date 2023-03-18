# sniffer
##项目功能
基于jpcap实现的网络嗅探器,项目主要主要功能为网络抓包，可以抓取5层协议的数据包，包括TCP、UDP、ICMP、IP、ARP等常见协议，
并支持按照协议、源IP、目的IP或关键字对抓取的包筛选。项目另外实现了基于Java Swing的GUI，便于操作。
##项目所需依赖
windows平台下需要下载安装winpcap与jpcap \
winpcap官网下载即可 \
jpcap 64位附百度网盘连接
```aidl
https://pan.baidu.com/s/1olfe7TZkAXCgWNIUleFNJw?pwd=ccnd
```
下载解压后将jpcap.dll文件放在安装路径
```aidl
jdk\jre\bin
```
将jpcap.jar文件添加到项目依赖即可 \
GUI界面的实现基于idea自带swing ui designer，需确保 UI Designer插件可用
##项目结构
项目主要由两部分组成，分别为 \
control包，实现后台抓包与分析 \
show包，实现GUI界面
##项目启动
项目的启动入口为UIForm.java文件下的main函数，直接运行即可


