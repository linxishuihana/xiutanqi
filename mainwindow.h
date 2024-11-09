#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <pcap.h>
#include <QThread>
#include <QDebug>
#include <QTableWidgetItem>


QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
namespace PacketHeaders {

struct EtherHeader {
    u_char ether_dhost[6];    // 目标MAC地址（6字节）
    u_char ether_shost[6];    // 源MAC地址（6字节）
    u_short ether_type;       // 以太网类型，标识网络层协议（例如：0x0800为IPv4，0x0806为ARP）
};

struct IPHeader {
    unsigned char version : 4;  // IP协议版本（4位）
    unsigned char header_length : 4;  // IP头部长度（4位，单位为4字节）
    u_char tos;                 // 服务类型（Type of Service）
    u_short total_length;       // 数据包总长度（包括IP头和数据部分）
    u_short identification;     // 标识符，用于分片时标识数据包
    u_short flags_offset;       // 标志和偏移量（用于分片）
    u_char ttl;                 // 生存时间（Time To Live），数据包在网络中的最大跳数
    u_char protocol;            // 上层协议（例如：6为TCP，17为UDP，1为ICMP）
    u_short checksum;           // IP头部校验和
    u_int src_addr;             // 源IP地址（32位）
    u_int dst_addr;             // 目标IP地址（32位）
};

struct IPv6Header {
    u_int version_class_flow;  // 版本（4位）、流量类别（8位）和流标签（20位）
    u_short payload_length;    // 载荷长度（不包括IPv6头部）
    u_char next_header;        // 下一个头部类型（例如：6为TCP，17为UDP）
    u_char hop_limit;          // 跳数限制（类似于IPv4的TTL）
    u_char src_addr[16];       // 源IPv6地址（128位）
    u_char dst_addr[16];       // 目标IPv6地址（128位）
};

struct TCPHeader {
    u_short src_port;          // 源端口号（2字节）
    u_short dst_port;          // 目标端口号（2字节）
    u_int sequence_number;     // 序列号（4字节）
    u_int acknowledgment_number; // 确认号（4字节）
    unsigned char reserved : 4, offset : 4;  // 保留位（4位）和数据偏移（4位）
    u_char flags;              // 标志位（如：SYN、ACK、FIN等）
    u_short window_size;       // 窗口大小（用于流量控制）
    u_short checksum;          // 校验和
    u_short urgent_pointer;    // 紧急指针
};

struct UDPHeader {
    u_short src_port;          // 源端口号（2字节）
    u_short dst_port;          // 目标端口号（2字节）
    u_short length;            // UDP数据包长度（包括UDP头和数据部分）
    u_short checksum;          // 校验和
};

struct ICMPHeader {
    u_char type;               // 类型（例如：0表示回显应答，8表示回显请求）
    u_char code;               // 代码（用于表示具体的ICMP错误）
    u_short checksum;          // 校验和
    u_short id;                // 标识符（用于标识ICMP报文）
    u_short sequence;          // 序列号（用于跟踪ICMP报文）
    u_int init_time;           // 初始时间戳
    u_short recv_time;         // 接收时间戳
    u_short send_time;         // 发送时间戳
};

struct ARPHeader {
    u_short hardware_type;     // 硬件类型（例如：0x01为以太网）
    u_short protocol_type;     // 协议类型（例如：0x0800为IPv4）
    u_char hardware_length;    // 硬件地址长度（例如：6字节为MAC地址）
    u_char protocol_length;    // 协议地址长度（例如：4字节为IPv4地址）
    u_short operation_code;    // 操作码（例如：1为请求，2为应答）
    u_char src_mac[6];         // 源MAC地址（6字节）
    u_char src_ip[4];          // 源IP地址（4字节）
    u_char dst_mac[6];         // 目标MAC地址（6字节）
    u_char dst_ip[4];          // 目标IP地址（4字节）
};

struct GREHeader {
    u_short flags_version;     // GRE标志和版本（包括版本号、协议标志等）
    u_short protocol_type;     // GRE协议类型，标识传输的上层协议类型
};

struct ESPHeader {
    u_int spi;                 // 安全参数索引（Security Parameters Index）
    u_int sequence_number;     // 序列号（用于标识ESP数据流中的每个包）
};

struct OSPFHeader {
    u_char version;            // OSPF版本
    u_char type;               // 报文类型（例如：Hello报文、LSA更新报文等）
    u_short packet_length;     // OSPF报文的总长度
    u_int router_id;           // 路由器ID
    u_int area_id;             // 区域ID
    u_short checksum;          // 校验和
    u_short autype;            // 认证类型
};

struct MPLSHeader {
    u_int label_stack_entry;   // 标签堆栈项（包括标签值、实验、S位和TTL）
};

}
QT_END_NAMESPACE



// 捕获线程类，继承自QThread用于在后台线程中执行数据包捕获操作
class CaptureThread : public QThread {
    Q_OBJECT

public:
    // 构造函数，接受设备名和过滤表达式，并调用父类构造函数
    explicit CaptureThread(const char* device, const QString& filterExpression, QObject* parent = nullptr);
    void run() override;  // 重载的run()函数，会在子线程中执行捕获操作
    void stop();          // 停止捕获线程的函数，通过设置stopCapture标志，安全地停止捕获过程

signals:
    // 数据包捕获信号，将捕获到的数据包信息传递到主线程
    void packetCaptured(const QByteArray& packetData, const QString& packet_tex, const QString& time, const QString& srcMac,
                        const QString& destMac, int length, const QString& protocolType, const QString& srcIp,
                        const QString& destIp);

    // 错误信号，捕获到错误时传递错误信息
    void error(const QString& errorMsg);

private:
    const char* deviceName;       // 网络设备名称
    QString filterExpression;     // 用于存储过滤条件
    bool stopCapture;             // 标记是否停止数据包捕获

    // 静态函数，处理捕获到的数据包
    static void packetHandler(uchar* args, const struct pcap_pkthdr* header, const uchar* packet);
};



// 主窗口类，用于显示和管理网络数据包捕获的操作
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // 函数
    MainWindow(QWidget *parent = nullptr);                     // 构造函数，初始化主窗口
    ~MainWindow();                                             // 析构函数，销毁主窗口时释放资源
    void displayPacketInTree(const QByteArray& packet_data);   // 将捕获到的数据包显示在层级图中

    // 数据
    int devCount;                        // 当前可用网卡设备数量
    pcap_if_t* allAdapters;              // 所有网络适配器的链表（通过pcap库获取）
    pcap_if_t* dev;                      // 当前选定的网络适配器
    char errbuf[PCAP_ERRBUF_SIZE];       // 用于存储捕获过程中的错误信息
    int index = 0;                       // 选择的适配器的索引
    CaptureThread *captureThread;        // 用于捕获数据包的线程对象
    QVector<QString> packet_tex_all;     // 保存捕获到的数据包的文本描述
    QVector<QByteArray> packet_data_all; // 保存捕获到的数据包的原始数据

private slots:
    // 槽函数：将捕获的数据包添加到列表（显示在界面上）
    void addPacket(const QByteArray& packetData, const QString& packet_tex, const QString& time, const QString& srcMac,
                   const QString& destMac, int length, const QString& protocolType, const QString& srcIp,
                   const QString& destIp);
    // 槽函数：开始捕获数据包
    void startCapture();
    // 槽函数：处理捕获过程中的错误信息
    void handleError(const QString& errorMsg);
    // 槽函数：停止捕获数据包
    void stopCapture();
    // 槽函数：点击数据包列表项时触发，在下方显示数据包详细信息
    void on_packet_list_itemClicked(QTableWidgetItem* item);

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
