#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <stdbool.h>
#include <time.h>

#define FILTER "ip and udp"
//流量告警0.5M
#define LIMIT 524288
//统计数据长度时间间隔间隔20s
#define STATISTIC_TIME 20000
//CSV目录
#define CSV_FILE_PATH "csv.txt"

//IP地址
typedef struct IP_ADDR {
	u_char byte0;
	u_char byte1;
	u_char byte2;
	u_char byte3;
}IP_ADDR;

//MAC地址
typedef struct MAC_ADDR {
	u_char byte0;
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
}MAC_ADDR;

//判断IP和Mac地址是否相等
bool Equal(IP_ADDR* IP_ADDR_0, IP_ADDR* IP_ADDR_1, MAC_ADDR* MAC_ADDR_0, MAC_ADDR* MAC_ADDR_1) {
	if ((IP_ADDR_0->byte0 == IP_ADDR_1->byte0) && (IP_ADDR_0->byte1 == IP_ADDR_1->byte1) &&
		(IP_ADDR_0->byte2 == IP_ADDR_1->byte2) && (IP_ADDR_0->byte3 == IP_ADDR_1->byte3))
	{
		if ((MAC_ADDR_0->byte0 == MAC_ADDR_1->byte0) && (MAC_ADDR_0->byte1 == MAC_ADDR_1->byte1) &&
			(MAC_ADDR_0->byte2 == MAC_ADDR_1->byte2) && (MAC_ADDR_0->byte3 == MAC_ADDR_1->byte3) &&
			(MAC_ADDR_0->byte4 == MAC_ADDR_1->byte4) && (MAC_ADDR_0->byte5 == MAC_ADDR_1->byte5))
			return true;//相等
		else return false;
	}
	else return false;
}


//CSV日志记录内容
typedef struct CSV_FORMAT {
	struct tm* time;	//时间
	MAC_ADDR srcMac;		//源MAC地址
	IP_ADDR srcIP;			//源IP地址
	MAC_ADDR desMac;		//目的MAC地址
	IP_ADDR desIP;			//目的IP地址
	int len;				//帧长度
}CSV_FORMAT;

//流量记录
typedef struct FLOW_STATEMENT {
	MAC_ADDR MAC;		//源/目的MAC地址
	IP_ADDR IP;			//源/目的IP地址
	unsigned total;	//一段时间内的总流量
}FLOW_STATEMENT;


//流量记录表
typedef struct FLOW_LIST {
	FLOW_STATEMENT* HEAD;//表头
	int length;//表长
}FLOW_LIST;

FLOW_LIST* flow_alarm_list;//限制表
FLOW_LIST* flow_recv_list;//受到表
FLOW_LIST* flow_send_list;//发送表

//设备列表
pcap_if_t* all_devs;

//输出文件
FILE* fp = NULL;

//警报间隔计时
ULONGLONG last_sec;

//本设备MAC地址
MAC_ADDR self_mac_addr;

//统计表输出计时
ULONGLONG last_recv_output;
ULONGLONG last_send_output;

//获取设备网卡列表
pcap_if_t* getAllDevs() {
	char error[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&all_devs, error) == -1) {
		printf("错误: %s\n", error);
		exit(-1);
	}
	return all_devs;
}

//输出设备列表（返回列表长度）
int printAllDevs() {
	int DevsCount = 0;
	for (pcap_if_t* d = all_devs; d; d = d->next) {
		printf("%d. %s", ++DevsCount, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	return DevsCount;
}

//选择设备（返回设备信息）
pcap_if_t* selectDev(int DevsCount) {
	int choice;
	printf("\n请输入设备序号(1-%d):", DevsCount);
	scanf("%d", &choice);

	if (choice <= 0 || choice > DevsCount) {
		printf("设备号应在(1-%d)间，实际输入为%d，输入超限！\n", DevsCount, choice);
		pcap_freealldevs(all_devs);//释放设备列表
		exit(-1);
	}
	pcap_if_t* current_dev;

	//定位到该设备
	int temp_index = 0;
	for (current_dev = all_devs; temp_index < choice - 1; current_dev = current_dev->next, temp_index++);
	return current_dev;
}

//获取句柄
pcap_t* getHandle(pcap_if_t* dev) {
	pcap_t* handle;
	char error[PCAP_ERRBUF_SIZE];

	//打开接口
	if ((handle = pcap_open_live(dev->name, 65536, 1, 1000, error)) == NULL) {
		printf("未能打开接口适配器，WinPcap不支持%s", dev->name);
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//检查是否在以太网
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("此程序只在以太网网络上工作！\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}
	return handle;
}

//设置过滤器
void setfilter(pcap_t* handle, u_int netmask) {
	struct bpf_program fcode;
	//检查过滤器格式
	if (pcap_compile(handle, &fcode, FILTER, 1, netmask) < 0) {
		printf("过滤器格式错误！\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//设置过滤器
	if (pcap_setfilter(handle, &fcode) < 0) {
		printf("设置过滤器时出错！\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}
}

//从收到的数据包中提取出用于输出和写入CSV的数据
CSV_FORMAT* pkt_to_csv(const struct pcap_pkthdr* header, const u_char* pkt_data) {
	struct CSV_FORMAT* csv_format = (struct CSV_FORMAT*)malloc(sizeof(struct CSV_FORMAT));
	if (csv_format == NULL)exit(-1);
	//时间
	time_t local_tv_sec = header->ts.tv_sec;
	csv_format->time = localtime(&local_tv_sec);
	//源/目的IP/MAC地址
	csv_format->srcMac = *(MAC_ADDR*)(pkt_data + 0x06);
	csv_format->srcIP = *(IP_ADDR*)(pkt_data + 0x1A);
	csv_format->desMac = *(MAC_ADDR*)(pkt_data);
	csv_format->desIP = *(IP_ADDR*)(pkt_data + 0x1E);
	//长度
	csv_format->len = header->len;
	return csv_format;
}

//生成用于输出和写入CSV的字符串
char* CSVFORMAT_to_str(CSV_FORMAT* csv_format) {

	//输出时间
	char timestr[20];
	strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", csv_format->time);

	char src_mac_str[18];//源Mac地址
	char src_ip_str[16];//源ip地址
	char des_mac_str[18];//目的Mac地址
	char des_ip_str[16];//目的ip地址

	//输出源MAC地址
	sprintf(src_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->srcMac.byte0,
		csv_format->srcMac.byte1,
		csv_format->srcMac.byte2,
		csv_format->srcMac.byte3,
		csv_format->srcMac.byte4,
		csv_format->srcMac.byte5);
	//输出源IP地址
	sprintf(src_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->srcIP.byte0,
		csv_format->srcIP.byte1,
		csv_format->srcIP.byte2,
		csv_format->srcIP.byte3);
	//输出目的MAC地址
	sprintf(des_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->desMac.byte0,
		csv_format->desMac.byte1,
		csv_format->desMac.byte2,
		csv_format->desMac.byte3,
		csv_format->desMac.byte4,
		csv_format->desMac.byte5);
	//输出目的IP地址
	sprintf(des_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->desIP.byte0,
		csv_format->desIP.byte1,
		csv_format->desIP.byte2,
		csv_format->desIP.byte3);

	char result[100];
	//输出完整字符串
	sprintf(result, "%s,%s,%s,%s,%s,%d",
		timestr,
		src_mac_str,
		src_ip_str,
		des_mac_str,
		des_ip_str,
		csv_format->len);

	return result;
}


//流量统计
void add_alarm_flow(MAC_ADDR* mac_addr, IP_ADDR* ip_addr, int flow) {
	//流量重置
	if (GetTickCount64() - last_sec >= 1000) {
		for (int i = 0; i < flow_alarm_list->length; ++i) {
			(flow_alarm_list->HEAD + i)->total = 0;
		}
		last_sec = GetTickCount64();
	}

	//流量统计
	bool isFound = false;
	for (int i = 0; i < flow_alarm_list->length; ++i) {
		if (Equal(ip_addr, &(flow_alarm_list->HEAD + i)->IP, mac_addr, &(flow_alarm_list->HEAD + i)->MAC))
		{
			(flow_alarm_list->HEAD + i)->total += flow;
			isFound = true;
		}
	}

	if (!isFound) {
		++(flow_alarm_list->length);
		if ((flow_alarm_list->HEAD = (FLOW_STATEMENT*)realloc(flow_alarm_list->HEAD, (flow_alarm_list->length) * sizeof(FLOW_STATEMENT))) == NULL)
			exit(-1);
		if ((flow_alarm_list->HEAD + flow_alarm_list->length - 1) == NULL)
			exit(-1);
		(flow_alarm_list->HEAD + flow_alarm_list->length - 1)->MAC = *mac_addr;
		(flow_alarm_list->HEAD + flow_alarm_list->length - 1)->IP = *ip_addr;
		(flow_alarm_list->HEAD + flow_alarm_list->length - 1)->total = flow;
	}

	//流量超过阈值告警
	for (int i = 0; i < flow_alarm_list->length; ++i) {
		if ((flow_alarm_list->HEAD + i)->total >= LIMIT) {
			printf("%02X-%02X-%02X-%02X-%02X-%02X,%3d:%3d:%3d:%3d的流量超出阈值！\n",
				(flow_alarm_list->HEAD + i)->MAC.byte0,
				(flow_alarm_list->HEAD + i)->MAC.byte1,
				(flow_alarm_list->HEAD + i)->MAC.byte2,
				(flow_alarm_list->HEAD + i)->MAC.byte3,
				(flow_alarm_list->HEAD + i)->MAC.byte4,
				(flow_alarm_list->HEAD + i)->MAC.byte5,
				(flow_alarm_list->HEAD + i)->IP.byte0,
				(flow_alarm_list->HEAD + i)->IP.byte1,
				(flow_alarm_list->HEAD + i)->IP.byte2,
				(flow_alarm_list->HEAD + i)->IP.byte3);
		}
	}
}

//接收统计
void add_recv_flow(MAC_ADDR* mac_addr, IP_ADDR* ip_addr, int flow) {
	//流量统计
	bool isFound = false;
	for (int i = 0; i < flow_recv_list->length; ++i) {
		if (Equal(ip_addr, &(flow_recv_list->HEAD + i)->IP, mac_addr, &(flow_recv_list->HEAD + i)->MAC))
		{
			(flow_recv_list->HEAD + i)->total += flow;
			isFound = true;
		}
	}

	if (!isFound) {
		++(flow_recv_list->length);
		if ((flow_recv_list->HEAD = (FLOW_STATEMENT*)realloc(flow_recv_list->HEAD, (flow_recv_list->length) * sizeof(FLOW_STATEMENT))) == NULL)
			exit(-1);
		if ((flow_recv_list->HEAD + flow_recv_list->length - 1) == NULL)
			exit(-1);
		(flow_recv_list->HEAD + flow_recv_list->length - 1)->MAC = *mac_addr;
		(flow_recv_list->HEAD + flow_recv_list->length - 1)->IP = *ip_addr;
		(flow_recv_list->HEAD + flow_recv_list->length - 1)->total = flow;
	}

	//统计输出
	if ((GetTickCount64() - last_recv_output) >= STATISTIC_TIME) {
		printf("\n统计来自不同 MAC 和 IP 地址的通信数据长度:\n");
		for (int i = 0; i < flow_recv_list->length; ++i) {
			printf("Mac Address :%02X-%02X-%02X-%02X-%02X-%02X, IP Address:%3d:%3d:%3d:%3d, 通信数据长度:%d\n",
				(flow_recv_list->HEAD + i)->MAC.byte0,
				(flow_recv_list->HEAD + i)->MAC.byte1,
				(flow_recv_list->HEAD + i)->MAC.byte2,
				(flow_recv_list->HEAD + i)->MAC.byte3,
				(flow_recv_list->HEAD + i)->MAC.byte4,
				(flow_recv_list->HEAD + i)->MAC.byte5,
				(flow_recv_list->HEAD + i)->IP.byte0,
				(flow_recv_list->HEAD + i)->IP.byte1,
				(flow_recv_list->HEAD + i)->IP.byte2,
				(flow_recv_list->HEAD + i)->IP.byte3,
				(flow_recv_list->HEAD + i)->total);
		}
		printf("\n\n");
		last_recv_output = GetTickCount64();
	}
}

//发送统计
void add_send_flow(MAC_ADDR* mac_addr, IP_ADDR* ip_addr, int flow) {
	//流量统计
	bool isFound = false;

	for (int i = 0; i < flow_send_list->length; ++i) {
		if (Equal(ip_addr, &(flow_send_list->HEAD + i)->IP, mac_addr, &(flow_send_list->HEAD + i)->MAC))
		{
			(flow_send_list->HEAD + i)->total += flow;
			isFound = true;
		}

	}

	if (!isFound) {
		++(flow_send_list->length);
		if ((flow_send_list->HEAD = (FLOW_STATEMENT*)realloc(flow_send_list->HEAD, (flow_send_list->length) * sizeof(FLOW_STATEMENT))) == NULL)
			exit(-1);
		if ((flow_send_list->HEAD + flow_send_list->length - 1) == NULL)
			exit(-1);
		(flow_send_list->HEAD + flow_send_list->length - 1)->MAC = *mac_addr;
		(flow_send_list->HEAD + flow_send_list->length - 1)->IP = *ip_addr;
		(flow_send_list->HEAD + flow_send_list->length - 1)->total = flow;
	}



	//统计输出
	if ((GetTickCount64() - last_send_output) >= STATISTIC_TIME) {
		printf("\n统计发至不同 MAC 和 IP 地址的通信数据长度:\n");
		for (int i = 0; i < flow_send_list->length; ++i) {
			printf("Mac Address :%02X-%02X-%02X-%02X-%02X-%02X,IP Address:%3d:%3d:%3d:%3d, 通信数据长度:%d\n",
				(flow_send_list->HEAD + i)->MAC.byte0,
				(flow_send_list->HEAD + i)->MAC.byte1,
				(flow_send_list->HEAD + i)->MAC.byte2,
				(flow_send_list->HEAD + i)->MAC.byte3,
				(flow_send_list->HEAD + i)->MAC.byte4,
				(flow_send_list->HEAD + i)->MAC.byte5,
				(flow_send_list->HEAD + i)->IP.byte0,
				(flow_send_list->HEAD + i)->IP.byte1,
				(flow_send_list->HEAD + i)->IP.byte2,
				(flow_send_list->HEAD + i)->IP.byte3,
				(flow_send_list->HEAD + i)->total);
		}
		printf("\n\n");
		last_send_output = GetTickCount64();
	}
}

//监听事件
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	(VOID)(param);
	struct CSV_FORMAT* csv = pkt_to_csv(header, pkt_data);
	add_alarm_flow(&csv->srcMac, &csv->srcIP, csv->len);
	add_recv_flow(&csv->desMac, &csv->desIP, csv->len);
	add_send_flow(&csv->srcMac, &csv->srcIP, csv->len);

	char output[100];
	strcpy(output, CSVFORMAT_to_str(csv));
	printf("%s\n", output);//输出至屏幕
	fprintf(fp, "%s\n", output);//输出至文件
}


//主函数
int main() {
	//打开文件
	fp = fopen(CSV_FILE_PATH, "w");

	//初始化流量统计
	//流量警告表
	if ((flow_alarm_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_alarm_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_alarm_list->length = 0;

	//流量发送表
	if ((flow_recv_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_recv_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_recv_list->length = 0;

	//流量接收表
	if ((flow_send_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_send_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_send_list->length = 0;

	//设备选择
	pcap_if_t* alldevs = getAllDevs();//获取设备列表
	int DevsCount = printAllDevs();//输出设备列表

	if (DevsCount == 0) {
		printf("\n错误，未发现Winpcap\n");
		return -1;
	}

	pcap_if_t* current_dev = selectDev(DevsCount);//选择设备
	//获取句柄
	pcap_t* handle = getHandle(current_dev);

	//设置掩码
	u_int netmask;
	if (current_dev->addresses != NULL)//当前设备地址不为空则取掩码
		netmask = ((struct sockaddr_in*)(current_dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;//假设设备在C类以太网上运行，掩码为0xFFFFFF

	//过滤器
	setfilter(handle, netmask);

	//监听准备
	printf("开始监听:%s\n", current_dev->description);
	pcap_freealldevs(alldevs);//释放设备列表
	last_sec = GetTickCount64();
	last_recv_output = GetTickCount64();
	last_send_output = GetTickCount64();

	//开始监听
	pcap_loop(handle, 0, packet_handler, NULL);

	return 0;

}