package src.controll;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;

import java.awt.*;
import java.util.ArrayList;
import java.util.Map;

//处理包的回调函数
public class Receiver implements PacketReceiver {
    public static ArrayList<Map<String,String>>messages=new ArrayList<Map<String, String>>();

    Map<String,String>message;
    @Override
    public void receivePacket(Packet packet) {
        message=new PacketAnalyze(packet).analyze();
        synchronized (Receiver.class){
            messages.add(message);
        }
    }

}
