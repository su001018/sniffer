package src.controll;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;

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

    public Map<String, String> getFilter() {
        return filter;
    }

    public void setFilter(Map<String, String> filter) {
        this.filter = filter;
    }

    //过滤信息
    Map<String,String> filter;
    //展示信息
    DefaultTableModel tableModel;

    public boolean isWork() {
        return work;
    }

    public void setWork(boolean work) {
        this.work = work;
    }

    //是否工作
    boolean work;

    public ArrayList<Map<String, String>> getPacketsDetails() {
        return packetsDetails;
    }

    //包详细信息
    ArrayList<Map<String, String>> packetsDetails;
    //日期
    SimpleDateFormat format=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public PacketCapture() {
        filter = new HashMap<>();
        packets = new ArrayList<>();
        packetsDetails = new ArrayList<>();
    }

    public PacketCapture(NetworkInterface networkCard) {
        this.device = networkCard;
        filter = new HashMap<>();
        packets = new ArrayList<>();
        packetsDetails = new ArrayList<>();
    }

    @Override
    public void run() {

        while (true) {
            try {
                JpcapCaptor jpcapCaptor = JpcapCaptor.openDevice(device, 65535, true, 2000);
                Packet packet = jpcapCaptor.getPacket();
                if (packet != null && check(packet)) {
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

    boolean check(Packet packet){
        Map<String, String> detail = new PacketAnalyze(packet).analyze();
        for(Map.Entry<String,String>entry:filter.entrySet()){
            String k=entry.getKey();
            String v=entry.getValue().trim();
            if(k.equals("keyword")&&!v.equals("")){
                boolean ff=false;
                for(Map.Entry<String,String>e:detail.entrySet()){
                    if(e.getKey().contains(v)||e.getValue().contains(v)){
                        ff=true;
                        break;
                    }
                }
                if(!ff)return false;
            }else if(k.equals("源IP")){
                if(!detail.containsKey("源IP")||!detail.get("源IP").contains(v))return false;
            }else if(k.equals("目的IP")){
                if(!detail.containsKey("目的IP")||!detail.get("目的IP").contains(v))return false;
            }else if(k.equals("协议类型")){
                Set<String> protocols=new HashSet<String>(Arrays.asList("TCP","IP","UDP","ICMP","ARP"));
                if(v.equals("其他")&&protocols.contains(detail.get(k))){
                    return false;
                }
                if(!v.equals("全部")&&!v.equals(detail.get(k)))return false;
            }
        }
        return true;
    }


}
