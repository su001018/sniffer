package src;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import src.controll.NetworkCard;
import src.controll.Receiver;

import java.io.IOException;

class Main{
    public static void main(String args[]) throws IOException {
        NetworkInterface[] devices= NetworkCard.getNetworkCards();
        int n=devices.length;
        if(n>0){
            //测试PacketAnalyze类
            //参数 (指定网卡，抓取长度，混杂模式，超时时间)
            JpcapCaptor jpcapCaptor=JpcapCaptor.openDevice(devices[2],65535,true,2000);
            jpcapCaptor.processPacket(50,new Receiver());
            System.out.println(Receiver.messages);
        }
    }
}
