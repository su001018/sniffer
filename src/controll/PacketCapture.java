package src.controll;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

//抓包的线程
//主线程为UI窗口，该线程负责抓包
public class PacketCapture implements Runnable {
    public NetworkInterface getDevice() {
        return device;
    }

    public void setDevice(NetworkInterface device) {
        this.device = device;
    }

    public ArrayList<Packet> getPackets() {
        return packets;
    }

    public void setPackets(ArrayList<Packet> packets) {
        this.packets = packets;
    }

    public String getFilter() {
        return filter;
    }

    public void setFilter(String filter) {
        this.filter = filter;
    }

    public DefaultTableModel getTableModel() {
        return tableModel;
    }

    public void setTableModel(DefaultTableModel tableModel) {
        this.tableModel = tableModel;
    }

    //网卡设备
    NetworkInterface device;
    //抓到的包
    ArrayList<Packet> packets;
    //过滤信息
    String filter;
    //展示信息
    DefaultTableModel tableModel;

    public ArrayList<Map<String, String>> getPacketsDetails() {
        return packetsDetails;
    }

    //包详细信息
    ArrayList<Map<String, String>> packetsDetails;
    //日期
    SimpleDateFormat format=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public PacketCapture() {
        filter = "";
        packets = new ArrayList<>();
        packetsDetails = new ArrayList<>();
    }

    public PacketCapture(NetworkInterface networkCard) {
        this.device = networkCard;
        filter = "";
        packets = new ArrayList<>();
        packetsDetails = new ArrayList<>();
    }

    @Override
    public void run() {

        while (true) {
            try {
                JpcapCaptor jpcapCaptor = JpcapCaptor.openDevice(device, 65535, true, 2000);
                Packet packet = jpcapCaptor.getPacket();
                if (packet != null) {
                    packets.add(packet);
                    tableModel.addRow(getHeader(packet));
                }


            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    String[] getHeader(Packet packet) {
        Map<String, String> detail = new PacketAnalyze(packet).analyze();
        packetsDetails.add(detail);
        String[] res = new String[4];
        res[0] = String.valueOf(format.format(new Date()));
        res[1] = detail.getOrDefault("源IP", "未知");
        res[2] = detail.getOrDefault("目的IP", "未知");
        res[3] = detail.getOrDefault("协议类型", "未知");
        return res;

    }

    public void clearList(){
        packets.clear();
        packetsDetails.clear();
        tableModel.setRowCount(0);
    }


}
