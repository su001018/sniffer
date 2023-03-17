package src.controll;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class NetworkCard {
    public static NetworkInterface[] getNetworkCards(){
        //获取网卡列表
        return JpcapCaptor.getDeviceList();
    }
}
