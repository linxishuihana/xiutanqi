#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QDateTime>
#include <QInputDialog>
#include <winsock2.h>
#include <ws2tcpip.h>

// 构造函数：初始化捕获线程，设置设备名称、过滤表达式和停止标志
CaptureThread::CaptureThread(const char* device, const QString& filterExpression, QObject* parent)
    : QThread(parent), deviceName(device), filterExpression(filterExpression), stopCapture(false) {}


// 重在子线程中执行捕获操作
void CaptureThread::run() {
    // 1.打开指定网络设备
    char errbuf[PCAP_ERRBUF_SIZE];                                          // 错误信息缓冲区
    pcap_t* handle = pcap_open_live(deviceName, 65536, 1, 1000, errbuf);    // 打开指定的网络设备进行数据包捕获
    if (handle == nullptr) {                                                // 如果无法打开设备，发出错误信号并退出
        emit error(QString("无法打开适配器：%1").arg(errbuf));
        return;
    }
    // 2.设置过滤规则
    struct bpf_program fp;                                                  // 过滤规则结构
    if (!filterExpression.isEmpty()) {                                      // 检查是否有过滤表达式
        if (pcap_compile(handle, &fp, filterExpression.toStdString().c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) { // 编译过滤表达式
            emit error(QString("无法编译过滤表达式：%1").arg(pcap_geterr(handle)));                                // 如果编译失败，发出错误信号，关闭设备并退出
            pcap_close(handle);
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {                            // 根据过滤表达式设置过滤规则
            emit error(QString("无法设置过滤器：%1").arg(pcap_geterr(handle)));// 如果设置失败，发出错误信号，释放编译的过滤器，关闭设备并退出
            pcap_freecode(&fp);
            pcap_close(handle);
            return;
        }
        pcap_freecode(&fp);
    }
    // 3.开始捕获数据包
    while (!stopCapture) {
        pcap_loop(handle, 1, packetHandler, (u_char*)this); // 使用pcap_loop捕获一个数据包，并调用packetHandler进行处理
        if (stopCapture) {                                  // 若捕获停止标识为真，退出循环
            break;
        }
    }
    pcap_breakloop(handle);                                 // 退出捕获，使用pcap_breakloop停止当前捕获
    pcap_close(handle);                                     // 关闭设备，释放资源
}

// 停止捕获：将停止标志设置为true
void CaptureThread::stop() {
    stopCapture = true;
}

// 处理捕获的数据包，并将相应信息发送给主线程以进行解析和ui展示（解析得到ui界面上所需信息）
void CaptureThread::packetHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    // 1.转换数据包内容为十六进制和 ASCII 格式的可视化输出（即ui下方左侧栏）
    QString packet_tex;                          // 用于保存数据包的十六进制和 ASCII 表示
    for (int i = 0; i < header->len; i += 16) {  //每行16个字节
        QString hexPart, asciiPart;
        for (int j = 0; j < 16; ++j) {           // 逐字节处理数据包，将每行16字节转换为十六进制和 ASCII
            if (i + j < header->len) {
                hexPart.append(QString("%1 ").arg(packet[i + j], 2, 16, QChar('0')).toUpper());// 转换为两位十六进制字符
                char ch = static_cast<char>(packet[i + j]);
                asciiPart.append((ch >= 32 && ch <= 126) ? ch : '.');                          // 如果字符为可打印字符则显示，否则用 '.' 表示
            } else {                             // 补齐空位以对齐显示
                hexPart.append("   ");
                asciiPart.append(" ");
            }
        }
        packet_tex.append(hexPart.leftJustified(48, ' ') + " " + asciiPart.leftJustified(16, ' ') + "\n");// 将转换后的十六进制和 ASCII 部分添加到 packet_tex 中
    }

    // 2.解析ui中部表格所需信息
    QDateTime timestamp = QDateTime::currentDateTime();
    QString timeString = timestamp.toString("yyyy-MM-dd hh:mm:ss");     // 获取当前时间并格式化为字符串

    const PacketHeaders::EtherHeader* eth_header = reinterpret_cast<const PacketHeaders::EtherHeader*>(packet);
    u_short ether_type = ntohs(eth_header->ether_type);                 // 解析以太网头部，获取源和目的 MAC 地址
    QString srcMac, destMac;
    for (int i = 0; i < 6; i++) {                                       // 将每个字节转换为两位十六进制字符串，格式化 MAC 地址
        srcMac += QString("%1").arg(eth_header->ether_shost[i], 2, 16, QChar('0')).toUpper() + (i < 5 ? ":" : "");
        destMac += QString("%1").arg(eth_header->ether_dhost[i], 2, 16, QChar('0')).toUpper() + (i < 5 ? ":" : "");
    }

    int length = header->len;                                           // 获取数据包长度
    QString srcIp, destIp, protocol;                                    // 初始化源 IP、目的 IP 和协议，下面得到具体值
    // 根据以太网类型字段解析协议类型
    if (ether_type == 0x0800) { // IPv4 协议
        const PacketHeaders::IPHeader* ip_header = reinterpret_cast<const PacketHeaders::IPHeader*>(packet + sizeof(PacketHeaders::EtherHeader));
        struct in_addr src_addr, dst_addr;        // 提取源和目的 IPv4 地址
        src_addr.s_addr = ip_header->src_addr;
        dst_addr.s_addr = ip_header->dst_addr;

        srcIp = inet_ntoa(src_addr);              // IPv4 源地址
        destIp = inet_ntoa(dst_addr);             // IPv4 目的地址
        switch (ip_header->protocol) {            // 根据 IP 头部的协议字段解析不同的 IP 层协议类型
        case 1:
            protocol = "ICMP";
            break;
        case 2:
            protocol = "IGMP";
            break;
        case 6:
            protocol = "TCP";
            break;
        case 17:
            protocol = "UDP";
            break;
        case 47:
            protocol = "GRE";
            break;
        case 50:
            protocol = "ESP";
            break;
        case 51:
            protocol = "AH";
            break;
        case 89:
            protocol = "OSPF";
            break;
        default:
            protocol = "Other IP Protocol";
            break;
        }

    } else if (ether_type == 0x0806) { // ARP 协议
        protocol = "ARP";
        const PacketHeaders::ARPHeader* arp_header = reinterpret_cast<const PacketHeaders::ARPHeader*>(packet + sizeof(PacketHeaders::EtherHeader));

        // 提取源和目的 IP 地址
        srcIp = QString("%1.%2.%3.%4").arg(arp_header->src_ip[0]).arg(arp_header->src_ip[1]).arg(arp_header->src_ip[2]).arg(arp_header->src_ip[3]);
        destIp = QString("%1.%2.%3.%4").arg(arp_header->dst_ip[0]).arg(arp_header->dst_ip[1]).arg(arp_header->dst_ip[2]).arg(arp_header->dst_ip[3]);

    } else if (ether_type == 0x86DD) { // IPv6 协议
        protocol = "IPv6";
        const PacketHeaders::IPv6Header* ipv6_header = reinterpret_cast<const PacketHeaders::IPv6Header*>(packet + sizeof(PacketHeaders::EtherHeader));

        // 解析源和目的 IPv6 地址
        char src_ipv6[INET6_ADDRSTRLEN], dest_ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipv6_header->src_addr, src_ipv6, sizeof(src_ipv6));
        inet_ntop(AF_INET6, &ipv6_header->dst_addr, dest_ipv6, sizeof(dest_ipv6));
        srcIp = QString(src_ipv6);
        destIp = QString(dest_ipv6);

        switch (ipv6_header->next_header) { // 根据 IPv6 头部的 next header 字段解析上层协议类型
        case 1:
            protocol = "ICMPv6";
            break;
        case 6:
            protocol = "TCP";
            break;
        case 17:
            protocol = "UDP";
            break;
        case 58:
            protocol = "ICMPv6 Neighbor Discovery";
            break;
        case 43:
            protocol = "Routing Header";
            break;
        case 44:
            protocol = "Fragment Header";
            break;
        case 59:
            protocol = "No Next Header";
            break;
        default:
            protocol = "Other IPv6 Protocol";
            break;
        }

    } else if (ether_type == 0x8847) { // MPLS 协议
        protocol = "MPLS";

    } else if (ether_type == 0x8035) { // RARP 协议
        protocol = "RARP";

    } else {  // 未知协议类型
        protocol = "Unknown";
    }

    // 3.将数据包内容转换为字节数组以供进一步处理（用于后续生成ui右下侧栏）
    QByteArray packetData(reinterpret_cast<const char*>(packet), header->len);

    // 4.发射信号传递解析后的数据包信息
    CaptureThread* thread = reinterpret_cast<CaptureThread*>(args);    // 获取当前线程实例，用于访问类的成员和发射信号
    emit thread->packetCaptured(packetData, packet_tex, timeString, srcMac, destMac, length, protocol, srcIp, destIp);
}









MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), captureThread(nullptr)
{
    // 1.初始化
    ui->setupUi(this);                // 初始化用户界面
    this->setWindowTitle("Sniffer");  // 设置窗口标题为“Sniffer”

    // 2.配置数据包列表视图 (QTableWidget)
    ui->packet_list->setColumnCount(7);                                     // 设置列表的列数为 7
    ui->packet_list->setHorizontalHeaderLabels(QStringList() << tr("Time")  // 设置每一列的标题标签
                                                             << tr("Source IP")
                                                             << tr("Destination IP")
                                                             << tr("Protocol")
                                                             << tr("Length")
                                                             << tr("Source MAC")
                                                             << tr("Destination MAC"));
    ui->packet_list->setSelectionBehavior(QAbstractItemView::SelectRows);   // 设置行为为单行选择
    ui->packet_list->setSelectionMode(QAbstractItemView::SingleSelection);  // 设置模式为单选
    ui->packet_list->setEditTriggers(QAbstractItemView::NoEditTriggers);    // 禁止编辑数据
    ui->packet_list->setColumnWidth(0, 140);                                // 时间列宽度为 140
    ui->packet_list->setColumnWidth(1, 150);                                // 源IP列宽度为 150
    ui->packet_list->setColumnWidth(2, 150);                                // 目的IP列宽度为 150
    ui->packet_list->setColumnWidth(3, 70);                                 // 协议列宽度为 70
    ui->packet_list->setColumnWidth(4, 60);                                 // 长度列宽度为 60
    ui->packet_list->setColumnWidth(5, 130);                                // 源MAC列宽度为 130
    ui->packet_list->setColumnWidth(6, 130);                                // 目的MAC列宽度为 130

    // 3.初始化网卡接口列表
    devCount = 0;                                                           // 初始化设备计数为 0
    if (pcap_findalldevs(&allAdapters, errbuf) == -1) {                     // 如果无法获取网卡接口信息，显示警告框提醒用户
        QMessageBox::warning(this, tr("Sniffer"), tr("无法在您的机器上获取网络适配器接口"), QMessageBox::Ok);
    } else {
        // 遍历所有网卡适配器并将描述信息添加到选择框（下拉菜单）中
        for (dev = allAdapters; dev; dev = dev->next) {
            devCount++;                                                     // 统计设备数量
            if (dev->description) {
                ui->select_nic->addItem(QString("%1").arg(dev->description));  // 添加描述到下拉框，供用户选择
            }
        }
    }
    // 4.设置文本框
    QFont fixedFont("Courier New");
    fixedFont.setStyleHint(QFont::Monospace);                               // 设置字体风格为等宽字体
    ui->textEdit->setFont(fixedFont);                                       // 应用此字体到文本框
    ui->textEdit->setReadOnly(true);                                        // 设置文本框只读模式
    // 5.设置过滤规则输入框的占位文本，提示用户输入捕获规则
    ui->filter_rule->setPlaceholderText("请设置捕获规则，若未设置规则则捕获所有数据包");

    // 6.连接用户界面按钮的点击信号到对应的槽函数
    connect(ui->str, &QPushButton::clicked, this, &MainWindow::startCapture);// 开始捕获按钮点击时调用 startCapture
    connect(ui->fin, &QPushButton::clicked, this, &MainWindow::stopCapture); // 停止捕获按钮点击时调用 stopCapture
    connect(ui->packet_list, &QTableWidget::itemClicked, this, &MainWindow::on_packet_list_itemClicked);  // 列表项被点击时调用 on_packet_list_itemClicked
}


// 析构函数，释放资源
MainWindow::~MainWindow()
{
    if (captureThread) {           // 如果捕获线程存在，先停止线程并释放资源
        captureThread->stop();     // 停止捕获线程
        captureThread->wait();     // 等待线程完全结束
        delete captureThread;      // 释放捕获线程内存
    }
    delete ui;                     // 删除 UI 资源
    pcap_freealldevs(allAdapters); // 释放网卡适配器列表资源
}

// 根据网卡和捕获规则从捕获线程处得到数据包信息
void MainWindow::startCapture() {
    if (ui->select_nic->currentIndex() == 0) {          // 如果用户未选择网卡接口，弹出警告框
        QMessageBox::warning(this, tr("Sniffer"), tr("请选择一个有效的网卡接口。"), QMessageBox::Ok);
        return;
    }
    int selectedIndex = ui->select_nic->currentIndex(); // 获取选定的网卡适配器
    dev = allAdapters;
    for (int i = 0; i < selectedIndex; ++i) {
        dev = dev->next;                                // 根据用户选择的索引找到相应的适配器
    }
    QString filterExpression = ui->filter_rule->text(); // 获取用户在过滤规则输入框中的表达式
    captureThread = new CaptureThread(dev->name, filterExpression, this);                  // 创建捕获线程对象
    connect(captureThread, &CaptureThread::packetCaptured, this, &MainWindow::addPacket);  // 当捕获数据包时，添加到列表
    connect(captureThread, &CaptureThread::error, this, &MainWindow::handleError);         // 处理捕获错误
    captureThread->start();                                                                // 启动捕获线程
}

// 捕获到新数据包时添加到ui界面的packet_list列表
void MainWindow::addPacket(const QByteArray& packetData, const QString& packet_tex, const QString& time, const QString& srcMac, const QString& destMac,
                           int length, const QString& protocolType, const QString& srcIp, const QString& destIp) {
    int rowCount = ui->packet_list->rowCount();
    ui->packet_list->insertRow(rowCount);                                       // 插入新行以显示新数据包信息
    ui->packet_list->setItem(rowCount, 0, new QTableWidgetItem(time));          // 时间
    ui->packet_list->setItem(rowCount, 1, new QTableWidgetItem(srcIp));         // 源IP地址
    ui->packet_list->setItem(rowCount, 2, new QTableWidgetItem(destIp));        // 目的IP地址
    ui->packet_list->setItem(rowCount, 3, new QTableWidgetItem(protocolType));  // 协议类型
    ui->packet_list->setItem(rowCount, 4, new QTableWidgetItem(QString::number(length))); // 数据包长度
    ui->packet_list->setItem(rowCount, 5, new QTableWidgetItem(srcMac));        // 源MAC地址
    ui->packet_list->setItem(rowCount, 6, new QTableWidgetItem(destMac));       // 目的MAC地址
    packet_data_all.append(packetData);  // 保存数据包的字节内容，存储在全局列表中以备后用
    packet_tex_all.append(packet_tex);   // 保存数据包的文本内容，存储在全局列表中以备后用
}

// 错误弹框
void MainWindow::handleError(const QString& errorMsg) {
    QMessageBox::critical(this, tr("Sniffer"), errorMsg);   // 捕获错误时，弹出一个消息框显示错误信息
}

// 停止捕获
void MainWindow::stopCapture() {
    if (captureThread) {
        captureThread->stop();   // 停止捕获线程
        captureThread->wait();   // 等待线程完全停止
        delete captureThread;    // 删除捕获线程对象
        captureThread = nullptr; // 重置指针为空
    }
}

// 捕获列表项被点击的槽函数（在下方两栏显示详细信息）
void MainWindow::on_packet_list_itemClicked(QTableWidgetItem* item) {
    int row = item->row();                              // 获取被点击的行索引
    if (row >= 0 && row < packet_tex_all.size()) {      // 检查行索引是否有效
        QString packet_tex = packet_tex_all[row];       // 获取对应的包文本信息
        ui->textEdit->setPlainText(packet_tex);         // 在文本框中显示数据包内容

        QByteArray packet_data = packet_data_all[row];  // 获取对应的数据包字节信息
        ui->treeWidget->clear();                        // 清空 treeWidget 的内容
        displayPacketInTree(packet_data);               // 调用函数解析并显示数据包的详细结构
    }
}

// 显示数据包的详细结构（右下方的树状框）
void MainWindow::displayPacketInTree(const QByteArray& packet_data) {
    const u_char* packet = reinterpret_cast<const u_char*>(packet_data.data());

    // 解析以太网头部
    const PacketHeaders::EtherHeader* eth_header = reinterpret_cast<const PacketHeaders::EtherHeader*>(packet);
    QTreeWidgetItem* ethItem = new QTreeWidgetItem(ui->treeWidget);
    ethItem->setText(0, "Ethernet Header");

    // 直接格式化和显示 MAC 地址
    QString destMacAddr;
    for (int i = 0; i < 6; ++i) {
        destMacAddr += QString("%1").arg(eth_header->ether_dhost[i], 2, 16, QChar('0')).toUpper() + (i < 5 ? ":" : "");
    }
    ethItem->addChild(new QTreeWidgetItem(ethItem, QStringList() << "Destination MAC: " + destMacAddr));

    QString srcMacAddr;
    for (int i = 0; i < 6; ++i) {
        srcMacAddr += QString("%1").arg(eth_header->ether_shost[i], 2, 16, QChar('0')).toUpper() + (i < 5 ? ":" : "");
    }
    ethItem->addChild(new QTreeWidgetItem(ethItem, QStringList() << "Source MAC: " + srcMacAddr));

    ethItem->addChild(new QTreeWidgetItem(ethItem, QStringList() << "Ether Type: " + QString::number(ntohs(eth_header->ether_type), 16)));

    // 解析 IP 头部
    if (ntohs(eth_header->ether_type) == 0x0800) { // IPv4
        const PacketHeaders::IPHeader* ip_header = reinterpret_cast<const PacketHeaders::IPHeader*>(packet + sizeof(PacketHeaders::EtherHeader));
        QTreeWidgetItem* ipItem = new QTreeWidgetItem(ui->treeWidget);
        ipItem->setText(0, "IP Header");
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Version: " + QString::number(ip_header->version)));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Header Length: " + QString::number(ip_header->header_length * 4)));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Type of Service: " + QString::number(ip_header->tos)));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Total Length: " + QString::number(ntohs(ip_header->total_length))));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Identification: " + QString::number(ntohs(ip_header->identification))));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Flags and Offset: " + QString::number(ntohs(ip_header->flags_offset))));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "TTL: " + QString::number(ip_header->ttl)));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Protocol: " + QString::number(ip_header->protocol)));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Header Checksum: " + QString::number(ntohs(ip_header->checksum))));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Source IP: " + QString::fromLatin1(inet_ntoa(*(struct in_addr*)&ip_header->src_addr))));
        ipItem->addChild(new QTreeWidgetItem(ipItem, QStringList() << "Destination IP: " + QString::fromLatin1(inet_ntoa(*(struct in_addr*)&ip_header->dst_addr))));

        // 检查上层协议（TCP/UDP/ICMP）
        int ipHeaderLength = ip_header->header_length * 4; // IP 头部长度
        const u_char* transport_header = packet + sizeof(PacketHeaders::EtherHeader) + ipHeaderLength;

        switch (ip_header->protocol) {
        case 6: // TCP
        {
            const PacketHeaders::TCPHeader* tcp_header = reinterpret_cast<const PacketHeaders::TCPHeader*>(transport_header);
            QTreeWidgetItem* tcpItem = new QTreeWidgetItem(ui->treeWidget);
            tcpItem->setText(0, "TCP Header");
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Source Port: " + QString::number(ntohs(tcp_header->src_port))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Destination Port: " + QString::number(ntohs(tcp_header->dst_port))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Sequence Number: " + QString::number(ntohl(tcp_header->sequence_number))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Acknowledgment Number: " + QString::number(ntohl(tcp_header->acknowledgment_number))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Offset: " + QString::number(tcp_header->offset * 4)));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Flags: " + QString::number(tcp_header->flags)));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Window Size: " + QString::number(ntohs(tcp_header->window_size))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Checksum: " + QString::number(ntohs(tcp_header->checksum))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Urgent Pointer: " + QString::number(ntohs(tcp_header->urgent_pointer))));
            break;
        }
        case 17: // UDP
        {
            const PacketHeaders::UDPHeader* udp_header = reinterpret_cast<const PacketHeaders::UDPHeader*>(transport_header);
            QTreeWidgetItem* udpItem = new QTreeWidgetItem(ui->treeWidget);
            udpItem->setText(0, "UDP Header");
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Source Port: " + QString::number(ntohs(udp_header->src_port))));
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Destination Port: " + QString::number(ntohs(udp_header->dst_port))));
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Length: " + QString::number(ntohs(udp_header->length))));
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Checksum: " + QString::number(ntohs(udp_header->checksum))));
            break;
        }
        case 1: // ICMP
        {
            const PacketHeaders::ICMPHeader* icmp_header = reinterpret_cast<const PacketHeaders::ICMPHeader*>(transport_header);
            QTreeWidgetItem* icmpItem = new QTreeWidgetItem(ui->treeWidget);
            icmpItem->setText(0, "ICMP Header");
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Type: " + QString::number(icmp_header->type)));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Code: " + QString::number(icmp_header->code)));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Checksum: " + QString::number(ntohs(icmp_header->checksum))));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "ID: " + QString::number(ntohs(icmp_header->id))));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Sequence: " + QString::number(ntohs(icmp_header->sequence))));
            break;
        }
        default:
            break;
        }
    }
    else if (ntohs(eth_header->ether_type) == 0x86DD) { // IPv6
        const PacketHeaders::IPv6Header* ipv6_header = reinterpret_cast<const PacketHeaders::IPv6Header*>(packet + sizeof(PacketHeaders::EtherHeader));
        QTreeWidgetItem* ipv6Item = new QTreeWidgetItem(ui->treeWidget);
        ipv6Item->setText(0, "IPv6 Header");

        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Version: " + QString::number((ntohl(ipv6_header->version_class_flow) >> 28) & 0xF)));
        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Traffic Class: " + QString::number((ntohl(ipv6_header->version_class_flow) >> 20) & 0xFF)));
        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Flow Label: " + QString::number(ntohl(ipv6_header->version_class_flow) & 0xFFFFF)));
        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Payload Length: " + QString::number(ntohs(ipv6_header->payload_length))));
        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Next Header: " + QString::number(ipv6_header->next_header)));
        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Hop Limit: " + QString::number(ipv6_header->hop_limit)));

        // 格式化 IPv6 地址
        char srcIp[INET6_ADDRSTRLEN], destIp[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ipv6_header->src_addr, srcIp, sizeof(srcIp));
        inet_ntop(AF_INET6, ipv6_header->dst_addr, destIp, sizeof(destIp));

        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Source IP: " + QString::fromLatin1(srcIp)));
        ipv6Item->addChild(new QTreeWidgetItem(ipv6Item, QStringList() << "Destination IP: " + QString::fromLatin1(destIp)));

        // 解析传输层协议
        const u_char* transport_header = packet + sizeof(PacketHeaders::EtherHeader) + sizeof(PacketHeaders::IPv6Header);

        switch (ipv6_header->next_header) {
        case 6: // TCP
        {
            const PacketHeaders::TCPHeader* tcp_header = reinterpret_cast<const PacketHeaders::TCPHeader*>(transport_header);
            QTreeWidgetItem* tcpItem = new QTreeWidgetItem(ui->treeWidget);
            tcpItem->setText(0, "TCP Header");
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Source Port: " + QString::number(ntohs(tcp_header->src_port))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Destination Port: " + QString::number(ntohs(tcp_header->dst_port))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Sequence Number: " + QString::number(ntohl(tcp_header->sequence_number))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Acknowledgment Number: " + QString::number(ntohl(tcp_header->acknowledgment_number))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Offset: " + QString::number(tcp_header->offset * 4)));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Flags: " + QString::number(tcp_header->flags)));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Window Size: " + QString::number(ntohs(tcp_header->window_size))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Checksum: " + QString::number(ntohs(tcp_header->checksum))));
            tcpItem->addChild(new QTreeWidgetItem(tcpItem, QStringList() << "Urgent Pointer: " + QString::number(ntohs(tcp_header->urgent_pointer))));
            break;
        }
        case 17: // UDP
        {
            const PacketHeaders::UDPHeader* udp_header = reinterpret_cast<const PacketHeaders::UDPHeader*>(transport_header);
            QTreeWidgetItem* udpItem = new QTreeWidgetItem(ui->treeWidget);
            udpItem->setText(0, "UDP Header");
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Source Port: " + QString::number(ntohs(udp_header->src_port))));
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Destination Port: " + QString::number(ntohs(udp_header->dst_port))));
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Length: " + QString::number(ntohs(udp_header->length))));
            udpItem->addChild(new QTreeWidgetItem(udpItem, QStringList() << "Checksum: " + QString::number(ntohs(udp_header->checksum))));
            break;
        }
        case 58: // ICMPv6
        {
            const PacketHeaders::ICMPHeader* icmp_header = reinterpret_cast<const PacketHeaders::ICMPHeader*>(transport_header);
            QTreeWidgetItem* icmpItem = new QTreeWidgetItem(ui->treeWidget);
            icmpItem->setText(0, "ICMPv6 Header");
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Type: " + QString::number(icmp_header->type)));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Code: " + QString::number(icmp_header->code)));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Checksum: " + QString::number(ntohs(icmp_header->checksum))));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "ID: " + QString::number(ntohs(icmp_header->id))));
            icmpItem->addChild(new QTreeWidgetItem(icmpItem, QStringList() << "Sequence: " + QString::number(ntohs(icmp_header->sequence))));
            break;
        }
        default:
            QTreeWidgetItem* unknownItem = new QTreeWidgetItem(ui->treeWidget);
            unknownItem->setText(0, "Unknown Transport Layer Protocol");
            unknownItem->addChild(new QTreeWidgetItem(unknownItem, QStringList() << "Protocol Number: " + QString::number(ipv6_header->next_header)));
            break;
        }
    }
    else if (ntohs(eth_header->ether_type) == 0x6558) { // GRE
        const PacketHeaders::GREHeader* gre_header = reinterpret_cast<const PacketHeaders::GREHeader*>(packet + sizeof(PacketHeaders::EtherHeader));
        QTreeWidgetItem* greItem = new QTreeWidgetItem(ui->treeWidget);
        greItem->setText(0, "GRE Header");
        greItem->addChild(new QTreeWidgetItem(greItem, QStringList() << "Flags and Version: " + QString::number(ntohs(gre_header->flags_version), 16)));
        greItem->addChild(new QTreeWidgetItem(greItem, QStringList() << "Protocol Type: " + QString::number(ntohs(gre_header->protocol_type), 16)));
    }
    else if (ntohs(eth_header->ether_type) == 0x0806) { // ARP
        const PacketHeaders::ARPHeader* arp_header = reinterpret_cast<const PacketHeaders::ARPHeader*>(packet + sizeof(PacketHeaders::EtherHeader));
        QTreeWidgetItem* arpItem = new QTreeWidgetItem(ui->treeWidget);
        arpItem->setText(0, "ARP Header");
        arpItem->addChild(new QTreeWidgetItem(arpItem, QStringList() << "Hardware Type: " + QString::number(ntohs(arp_header->hardware_type))));
        arpItem->addChild(new QTreeWidgetItem(arpItem, QStringList() << "Protocol Type: " + QString::number(ntohs(arp_header->protocol_type))));
        arpItem->addChild(new QTreeWidgetItem(arpItem, QStringList() << "Operation Code: " + QString::number(ntohs(arp_header->operation_code))));

        // 直接在此格式化 MAC 地址并显示
        QString srcMac;
        for (int i = 0; i < 6; ++i) {
            srcMac += QString("%1").arg(arp_header->src_mac[i], 2, 16, QChar('0')).toUpper() + (i < 5 ? ":" : "");
        }
        arpItem->addChild(new QTreeWidgetItem(arpItem, QStringList() << "Source MAC: " + srcMac));

        QString dstMac;
        for (int i = 0; i < 6; ++i) {
            dstMac += QString("%1").arg(arp_header->dst_mac[i], 2, 16, QChar('0')).toUpper() + (i < 5 ? ":" : "");
        }
        arpItem->addChild(new QTreeWidgetItem(arpItem, QStringList() << "Destination MAC: " + dstMac));

        // 格式化 ARP 的 IPv4 地址
        struct in_addr src_addr, dst_addr;
        std::memcpy(&src_addr, arp_header->src_ip, sizeof(src_addr));
        std::memcpy(&dst_addr, arp_header->dst_ip, sizeof(dst_addr));

        arpItem->addChild(new QTreeWidgetItem(arpItem, QStringList() << "Source IP: " + QString::fromLatin1(inet_ntoa(src_addr))));
        arpItem->addChild(new QTreeWidgetItem(arpItem, QStringList() << "Destination IP: " + QString::fromLatin1(inet_ntoa(dst_addr))));
    }

    else if (ntohs(eth_header->ether_type) == 0x88BE) { // MPLS
        const PacketHeaders::MPLSHeader* mpls_header = reinterpret_cast<const PacketHeaders::MPLSHeader*>(packet + sizeof(PacketHeaders::EtherHeader));
        QTreeWidgetItem* mplsItem = new QTreeWidgetItem(ui->treeWidget);
        mplsItem->setText(0, "MPLS Header");
        mplsItem->addChild(new QTreeWidgetItem(mplsItem, QStringList() << "Label Stack Entry: " + QString::number(ntohl(mpls_header->label_stack_entry), 16)));
    }
    else if (ntohs(eth_header->ether_type) == 0x0800) { // OSPF
        const PacketHeaders::OSPFHeader* ospf_header = reinterpret_cast<const PacketHeaders::OSPFHeader*>(packet + sizeof(PacketHeaders::EtherHeader));
        QTreeWidgetItem* ospfItem = new QTreeWidgetItem(ui->treeWidget);
        ospfItem->setText(0, "OSPF Header");
        ospfItem->addChild(new QTreeWidgetItem(ospfItem, QStringList() << "Version: " + QString::number(ospf_header->version)));
        ospfItem->addChild(new QTreeWidgetItem(ospfItem, QStringList() << "Type: " + QString::number(ospf_header->type)));
        ospfItem->addChild(new QTreeWidgetItem(ospfItem, QStringList() << "Packet Length: " + QString::number(ntohs(ospf_header->packet_length))));
        ospfItem->addChild(new QTreeWidgetItem(ospfItem, QStringList() << "Router ID: " + QString::number(ntohl(ospf_header->router_id))));
    }

    ui->treeWidget->expandAll(); // 展开所有项
}


