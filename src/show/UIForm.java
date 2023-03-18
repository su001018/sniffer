package src.show;

import jpcap.NetworkInterface;
import src.controll.NetworkCard;
import src.controll.PacketAnalyze;
import src.controll.PacketCapture;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.event.*;
import java.util.HashMap;
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
    private JButton stopButton;
    private JTextArea countTextArea;

    //抓包进程
    PacketCapture packetCapture;
    //现有线程
    Thread run;
    //获取统计信息线程
    Thread count;
    //网卡设备
    NetworkInterface[] devices;

    //表格头部
    String[] tableHeader={"时间","源IP","目的IP","协议类型"};
    //表格内容
    DefaultTableModel tableModel;
    //包的详细信息
    Map<String,String> detail;
    //协议类型
    String[] protocolTypes={"全部","TCP","UDP","ICMP","ARP","IP","其他"};
    //筛选条件
    Map<String,String>filter;

    public UIForm() {
        filter=new HashMap<>();
        packetCapture=new PacketCapture();
        run=new Thread(packetCapture);
        count=new Thread(new getCount());
        count.start();
        devices= NetworkCard.getNetworkCards();
        tableModel=new DefaultTableModel(new Object[][]{},tableHeader);
        //绑定数据源
        packetCapture.setTableModel(tableModel);
        for(int i=0;i<devices.length;i++){
            NetworkInterface device=devices[i];
            devicesComboBox.addItem("no."+i+" "+device.description);
        }
        if(devices.length>=3){
            devicesComboBox.setSelectedIndex(2);
        }else devicesComboBox.setSelectedIndex(0);

        for(int i=0;i<protocolTypes.length;i++){
            protocolComboBox.addItem(protocolTypes[i]);
        }
        protocolComboBox.setSelectedIndex(0);

        //网卡更换监听方法
        devicesComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if(e.getStateChange()==ItemEvent.SELECTED){
//                    packetCapture.setDevice(devices[devicesComboBox.getSelectedIndex()]);
//                    //更换网卡后结束原来线程
//                    if(run.getState()== Thread.State.RUNNABLE){
//                        run.stop();
//                    }
//                    //清空原数据
//                    packetCapture.clearList();
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

        //开始抓包
        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(run.getState()!= Thread.State.TERMINATED){
                    run.stop();
                }
                packetCapture.clearList();
                packetCapture.setFilter(filter);
                packetCapture.setDevice(devices[devicesComboBox.getSelectedIndex()]);
                run=new Thread(packetCapture);
                run.start();
            }
        });
        //停止抓包
        stopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(run.getState()==Thread.State.RUNNABLE){
                    run.stop();
                }
            }
        });

        //筛选协议
        protocolComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if(e.getStateChange()==ItemEvent.SELECTED){
                    filter.put("协议类型", String.valueOf(protocolComboBox.getSelectedItem()));
                }
            }
        });
        //源IP地址变化
        sipTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                filter.put("源IP", sipTextField.getText().trim());
            }
        });
        //目的IP地址变化
        dipTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                filter.put("目的IP", dipTextField.getText().trim());
            }
        });
        //关键字变化
        keywordTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                filter.put("keyword", keywordTextField.getText().trim());
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

    private class getCount implements Runnable{

        @Override
        public void run() {

            while(true){
                countTextArea.setText("");
                String[] counts= PacketAnalyze.getCountMessage();
                for(String count:counts){
                    countTextArea.append(count+'\n');
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }



//    public UIForm(){
//
//        setVisible(true);
//        setResizable(false);
//        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        setTitle("MySniffer");
//    }
}
