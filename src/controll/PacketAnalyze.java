package src.controll;

import jpcap.packet.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class PacketAnalyze {
    Packet packet;

    public PacketAnalyze(Packet packet) {
        this.packet = packet;
    }

    //统计获得的包的数据
    private static int packetCount = 0;
    private static int packetPacketCount = 0;
    private static int ipPacketCount = 0;
    private static int tcpPacketCount = 0;
    private static int udpPacketCount = 0;
    private static int icmpPacketCount = 0;
    private static int arpPacketCount = 0;
    private static int elsePacketCount = 0;

    public Map<String, String> analyze() {
        //加类锁，进行同步
        synchronized (PacketAnalyze.class) {
            packetCount++;
        }
        //返回关于包的信息
        Map<String, String> message = new HashMap<>();

        //数据链路层，每个包都有数据链路层的相关信息
        message.putAll(analyzeEthernetPacket());

        //判断包的类型
        //jpcap所能分析的类型
        if (packet instanceof jpcap.packet.Packet) {

            if (packet.getClass().equals(Packet.class)) {
                // 抓取到packet数据包,尚不清楚这些是什么数据包;
                synchronized (PacketAnalyze.class) {
                    packetPacketCount++;
                }

            }
            //IP协议的包
            else if (packet.getClass().equals(IPPacket.class)) {
                synchronized (PacketAnalyze.class) {
                    ipPacketCount++;
                }
                message.putAll(analyzeIPPacket());
            }
            // 传输层,显示数据包的 ICMP/ TCP/ UDP 首部
            else if (packet.getClass().equals(TCPPacket.class)) {
                synchronized (PacketAnalyze.class) {
                    tcpPacketCount++;
                }
                message.putAll(analyzeTCPPacket());
            } else if (packet.getClass().equals(UDPPacket.class)) {
                synchronized (PacketAnalyze.class) {
                    udpPacketCount++;
                }
                message.putAll(analyzeUDPPacket());
            } else if (packet.getClass().equals(ICMPPacket.class)) {
                synchronized (PacketAnalyze.class) {
                    icmpPacketCount++;
                }
                message.putAll(analyzeICMPPacket());
            }
            //网络层,显示ARP数据包的首部
            else if (packet.getClass().equals(ARPPacket.class)) {
                synchronized (PacketAnalyze.class) {
                    arpPacketCount++;
                }
                message.putAll(analyzeARPPacket());
            }
        } else {
            //加类锁，进行同步
            synchronized (PacketAnalyze.class) {
                elsePacketCount++;
            }
            message.put("协议类型", "GGP、EGP、JGP协议或OSPF协议或ISO的第4类运输协议TP4");
        }
        return message;

    }

    private Map<String, String> analyzeARPPacket() {
        ARPPacket arpPacket = (ARPPacket) packet;// 将 packet类转成 ARPPacket类;
        return new HashMap<String, String>() {{
            put("硬件类型hardtop", String.valueOf(arpPacket.hardtype));
            put("协议类型prototype", String.valueOf(arpPacket.prototype));
            put("操作字段operation", String.valueOf(arpPacket.operation));
            put("IP首部", arpPacket.toString());// String toString: 返回描述此数据包的字符串;
            put("发送方硬件地址", (String) arpPacket.getSenderHardwareAddress());
            put("接收方硬件地址", (String) arpPacket.getTargetHardwareAddress());
            put("发送方IP地址", (String) arpPacket.getSenderProtocolAddress());
            put("接收方IP地址", (String) arpPacket.getTargetProtocolAddress());
        }};
    }

    private Map<String, String> analyzeICMPPacket() {
        // ICMP数据报,ICMPPacket类继承 IPPacket类;
        ICMPPacket icmpPacket = (ICMPPacket) packet;
        return new HashMap<String, String>() {{
            put("ICMP报文首部", icmpPacket.toString());// 只包含报文类型和代码;
            put("标志位DF:是否允许分片", String.valueOf(icmpPacket.dont_frag));
            put("标志位MF:后面是否还有分片", String.valueOf(icmpPacket.more_frag));
            put("片偏移offset", String.valueOf(icmpPacket.offset));
            put("标识ident", String.valueOf(icmpPacket.ident));
            put("协议protocol", "ICMP报文");
            put("ICMP报文类型type", String.valueOf(icmpPacket.type));
            put("ICMP报文代码code", String.valueOf(icmpPacket.code));
        }};

    }

    private Map<String, String> analyzeUDPPacket() {
        // UDP数据报,UDPPacket类继承 IPPacket类;
        UDPPacket udpPacket = (UDPPacket) packet;
        return new HashMap<String, String>() {{
            put("UDP报文首部", udpPacket.toString());
            put("标志位DF:是否允许分片", String.valueOf(udpPacket.dont_frag));
            put("标志位MF:后面是否还有分片", String.valueOf(udpPacket.more_frag));
            put("片偏移offset", String.valueOf(udpPacket.offset));
            put("标识ident", String.valueOf(udpPacket.ident));
            put("协议protocol", "UDP报文");
            put("源端口src_port", String.valueOf(udpPacket.src_port));
            put("目的端口dst_port", String.valueOf(udpPacket.dst_port));
            put("UDP报文长度length", String.valueOf(udpPacket.length));
        }};
    }

    private Map<String, String> analyzeTCPPacket() {
        TCPPacket tcpPacket = (TCPPacket) packet;// 将 TCPPacket类转成 IPPacket类;
        return new HashMap<String, String>() {{
            put("TCP报文首部", tcpPacket.toString());
            put("标志位DF:是否允许分片", String.valueOf(tcpPacket.dont_frag));
            put("标志位MF:后面是否还有分片", String.valueOf(tcpPacket.more_frag));
            put("片偏移offset", String.valueOf(tcpPacket.offset));
            put("标识ident", String.valueOf(tcpPacket.ident));
            put("协议protocol", "TCP报文");
            put("源端口src_port", String.valueOf(tcpPacket.src_port));
            put("目的端口dst_port", String.valueOf(tcpPacket.dst_port));
            put("seq序号", String.valueOf(tcpPacket.sequence));
            put("窗口大小window", String.valueOf(tcpPacket.window));
            put("ACK标志", String.valueOf(tcpPacket.ack));// boolean ack :ACK标志
            put("ack", String.valueOf(tcpPacket.ack_num));// long ack_num :确认号
            put("TCP报文长度length", String.valueOf(tcpPacket.length));
        }};
    }

    private Map<String, String> analyzeEthernetPacket() {
        //以太帧
        EthernetPacket dataLink = (EthernetPacket) packet.datalink;
        return new HashMap<String, String>() {{
            put("以太帧首部", dataLink.toString());// 描述以太帧的字符串
            put("源mac地址", dataLink.getSourceAddress());// 源mac地址
            put("目的mac地址", dataLink.getDestinationAddress());// 目的mac地址
            put("帧类型", String.valueOf(dataLink.frametype));// 帧类型
        }};
    }

    private Map<String, String> analyzeIPPacket() {
        // IP数据包, IPPacket类继承 Packet类,包括 IPV4和 IPV6;
        IPPacket ipPacket = (IPPacket) packet;// 将 packet类转成 IPPacket类;
        return new HashMap<String, String>() {{
            put("IP报文首部", ipPacket.toString());
            put("版本version", String.valueOf(ipPacket.version));
            put("时间戳sec(秒)", String.valueOf(ipPacket.sec));
            put("时间戳usec(毫秒)", String.valueOf(ipPacket.usec));
            put("源IP", ipPacket.src_ip.getHostAddress());
            put("目的IP", ipPacket.dst_ip.getHostAddress());
            put("协议protocol", String.valueOf(ipPacket.protocol));
            put("优先权priority", String.valueOf(ipPacket.priority));
            put("生存时间hop", String.valueOf(ipPacket.hop_limit));
            put("标志位RF:保留位必须为false", String.valueOf(ipPacket.rsv_frag));
            put("标志位DF:是否允许分片", String.valueOf(ipPacket.dont_frag));
            put("标志位MF:后面是否还有分片", String.valueOf(ipPacket.more_frag));
            put("片偏移offset", String.valueOf(ipPacket.offset));
            put("标识ident", String.valueOf(ipPacket.ident));
            // 抓到的flowable 流标签的包,是ipv6数据包;
        }};

    }

    //获取统计信息
    public String[] getCountMessage(){
        synchronized (PacketAnalyze.class){
            ArrayList<String>res=new ArrayList<>();
            res.add("捕获到的数据包的总数为：" + packetCount);
            res.add("捕获到的packet数据包的总数为：" + packetPacketCount);
            res.add("捕获到ip数据包的总数为：" + ipPacketCount);
            res.add("捕获到icmp数据包的总数为：" + icmpPacketCount);
            res.add("捕获到tcp数据包的总数为：" + tcpPacketCount);
            res.add("捕获到udp数据包的总数为：" + udpPacketCount);
            res.add("捕获到arp数据包的总数为：" + arpPacketCount);
            res.add("捕获到其他数据包的总数为：" + elsePacketCount);
            return res.toArray(new String[res.size()]);
        }

    }

}
