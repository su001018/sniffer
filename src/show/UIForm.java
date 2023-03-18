package src.show;

import jpcap.NetworkInterface;
import src.controll.NetworkCard;
import src.controll.PacketCapture;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Map;

public class UIForm extends JFrame{
    private JPanel mainPanel;
    private JPanel headerPanel;
    private JPanel bodyPanel;
    private JPanel countPanel;
    private JPanel formPanel;
    private JPanel detailPanel;
    private JLabel deviceSelectLabel;
    private JComboBox devicesComboBox;
    private JTable packetsTable;
    private JScrollPane tableScrollPanel;
    private JLabel detailLabel;
    private JScrollPane detailScrollPanel;
    private JTextArea detailTextArea;
    private JLabel protocolLabel;
    private JComboBox protocolComboBox;
    private JLabel sipLabel;
    private JLabel dipLabel;
    private JTextField dipTextField;
    private JLabel keywordLabel;
    private JTextField keywordTextField;
    private JTextField sipTextField;
    private JButton startButton;

    //抓包进程
    PacketCapture packetCapture;
    //现有线程
    Thread run;
    //网卡设备
    NetworkInterface[] devices;

    //表格头部
    String[] tableHeader={"时间","源IP","目的IP","协议类型"};
    //表格内容
    DefaultTableModel tableModel;
    //包的详细信息
    Map<String,String> detail;
    //协议类型
    String[] protocolTypes={"TCP","UDP","ICMP","ARP","其他"};

    public UIForm() {
        packetCapture=new PacketCapture();
        run=new Thread(packetCapture);
        devices= NetworkCard.getNetworkCards();
        tableModel=new DefaultTableModel(new Object[][]{},tableHeader);
        //绑定数据源
        packetCapture.setTableModel(tableModel);
        for(int i=0;i<devices.length;i++){
            NetworkInterface device=devices[i];
            devicesComboBox.addItem("no."+i+" "+device.description);
        }

        //网卡更换监听方法
        devicesComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if(e.getStateChange()==ItemEvent.SELECTED){
                    packetCapture.setDevice(devices[devicesComboBox.getSelectedIndex()]);
                    //更换网卡后结束原来线程并新建线程
                    if(run.getState()== Thread.State.RUNNABLE){
                        run.stop();
                    }
                    //清空原数据
                    packetCapture.clearList();
                    run=new Thread(packetCapture);
                    run.start();
                }
            }
        });

        //展示包简略信息
        packetsTable.setModel(tableModel);
        packetsTable.setRowHeight(40);
        //双击展示详细信息
        packetsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(e.getClickCount()==1){
                    int row=packetsTable.rowAtPoint(e.getPoint());
                    detail=packetCapture.getPacketsDetails().get(row);
                    detailTextArea.setText("");
                    for (Map.Entry<String,String> entry:detail.entrySet()){
                        detailTextArea.append(entry.getKey()+'\n');
                        detailTextArea.append(entry.getValue()+'\n');
                    }
                }
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("UIForm");
        frame.setBounds(350, 50, 1200, 800);
        frame.setContentPane(new UIForm().mainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);


    }



//    public UIForm(){
//
//        setVisible(true);
//        setResizable(false);
//        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        setTitle("MySniffer");
//    }
}
