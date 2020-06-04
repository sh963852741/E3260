#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <stdbool.h>
#include <time.h>

#define FILTER "ip and udp"
//�����澯0.5M
#define LIMIT 524288
//ͳ�����ݳ���ʱ�������20s
#define STATISTIC_TIME 20000
//CSVĿ¼
#define CSV_FILE_PATH "csv.txt"

//IP��ַ
typedef struct IP_ADDR {
	u_char byte0;
	u_char byte1;
	u_char byte2;
	u_char byte3;
}IP_ADDR;

//MAC��ַ
typedef struct MAC_ADDR {
	u_char byte0;
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
}MAC_ADDR;

//�ж�IP��Mac��ַ�Ƿ����
bool Equal(IP_ADDR* IP_ADDR_0, IP_ADDR* IP_ADDR_1, MAC_ADDR* MAC_ADDR_0, MAC_ADDR* MAC_ADDR_1) {
	if ((IP_ADDR_0->byte0 == IP_ADDR_1->byte0) && (IP_ADDR_0->byte1 == IP_ADDR_1->byte1) &&
		(IP_ADDR_0->byte2 == IP_ADDR_1->byte2) && (IP_ADDR_0->byte3 == IP_ADDR_1->byte3))
	{
		if ((MAC_ADDR_0->byte0 == MAC_ADDR_1->byte0) && (MAC_ADDR_0->byte1 == MAC_ADDR_1->byte1) &&
			(MAC_ADDR_0->byte2 == MAC_ADDR_1->byte2) && (MAC_ADDR_0->byte3 == MAC_ADDR_1->byte3) &&
			(MAC_ADDR_0->byte4 == MAC_ADDR_1->byte4) && (MAC_ADDR_0->byte5 == MAC_ADDR_1->byte5))
			return true;//���
		else return false;
	}
	else return false;
}


//CSV��־��¼����
typedef struct CSV_FORMAT {
	struct tm* time;	//ʱ��
	MAC_ADDR srcMac;		//ԴMAC��ַ
	IP_ADDR srcIP;			//ԴIP��ַ
	MAC_ADDR desMac;		//Ŀ��MAC��ַ
	IP_ADDR desIP;			//Ŀ��IP��ַ
	int len;				//֡����
}CSV_FORMAT;

//������¼
typedef struct FLOW_STATEMENT {
	MAC_ADDR MAC;		//Դ/Ŀ��MAC��ַ
	IP_ADDR IP;			//Դ/Ŀ��IP��ַ
	unsigned total;	//һ��ʱ���ڵ�������
}FLOW_STATEMENT;


//������¼��
typedef struct FLOW_LIST {
	FLOW_STATEMENT* HEAD;//��ͷ
	int length;//��
}FLOW_LIST;

FLOW_LIST* flow_alarm_list;//���Ʊ�
FLOW_LIST* flow_recv_list;//�ܵ���
FLOW_LIST* flow_send_list;//���ͱ�

//�豸�б�
pcap_if_t* all_devs;

//����ļ�
FILE* fp = NULL;

//���������ʱ
ULONGLONG last_sec;

//���豸MAC��ַ
MAC_ADDR self_mac_addr;

//ͳ�Ʊ������ʱ
ULONGLONG last_recv_output;
ULONGLONG last_send_output;

//��ȡ�豸�����б�
pcap_if_t* getAllDevs() {
	char error[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&all_devs, error) == -1) {
		printf("����: %s\n", error);
		exit(-1);
	}
	return all_devs;
}

//����豸�б������б��ȣ�
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

//ѡ���豸�������豸��Ϣ��
pcap_if_t* selectDev(int DevsCount) {
	int choice;
	printf("\n�������豸���(1-%d):", DevsCount);
	scanf("%d", &choice);

	if (choice <= 0 || choice > DevsCount) {
		printf("�豸��Ӧ��(1-%d)�䣬ʵ������Ϊ%d�����볬�ޣ�\n", DevsCount, choice);
		pcap_freealldevs(all_devs);//�ͷ��豸�б�
		exit(-1);
	}
	pcap_if_t* current_dev;

	//��λ�����豸
	int temp_index = 0;
	for (current_dev = all_devs; temp_index < choice - 1; current_dev = current_dev->next, temp_index++);
	return current_dev;
}

//��ȡ���
pcap_t* getHandle(pcap_if_t* dev) {
	pcap_t* handle;
	char error[PCAP_ERRBUF_SIZE];

	//�򿪽ӿ�
	if ((handle = pcap_open_live(dev->name, 65536, 1, 1000, error)) == NULL) {
		printf("δ�ܴ򿪽ӿ���������WinPcap��֧��%s", dev->name);
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//����Ƿ�����̫��
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("�˳���ֻ����̫�������Ϲ�����\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}
	return handle;
}

//���ù�����
void setfilter(pcap_t* handle, u_int netmask) {
	struct bpf_program fcode;
	//����������ʽ
	if (pcap_compile(handle, &fcode, FILTER, 1, netmask) < 0) {
		printf("��������ʽ����\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//���ù�����
	if (pcap_setfilter(handle, &fcode) < 0) {
		printf("���ù�����ʱ����\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}
}

//���յ������ݰ�����ȡ�����������д��CSV������
CSV_FORMAT* pkt_to_csv(const struct pcap_pkthdr* header, const u_char* pkt_data) {
	struct CSV_FORMAT* csv_format = (struct CSV_FORMAT*)malloc(sizeof(struct CSV_FORMAT));
	if (csv_format == NULL)exit(-1);
	//ʱ��
	time_t local_tv_sec = header->ts.tv_sec;
	csv_format->time = localtime(&local_tv_sec);
	//Դ/Ŀ��IP/MAC��ַ
	csv_format->srcMac = *(MAC_ADDR*)(pkt_data + 0x06);
	csv_format->srcIP = *(IP_ADDR*)(pkt_data + 0x1A);
	csv_format->desMac = *(MAC_ADDR*)(pkt_data);
	csv_format->desIP = *(IP_ADDR*)(pkt_data + 0x1E);
	//����
	csv_format->len = header->len;
	return csv_format;
}

//�������������д��CSV���ַ���
char* CSVFORMAT_to_str(CSV_FORMAT* csv_format) {

	//���ʱ��
	char timestr[20];
	strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", csv_format->time);

	char src_mac_str[18];//ԴMac��ַ
	char src_ip_str[16];//Դip��ַ
	char des_mac_str[18];//Ŀ��Mac��ַ
	char des_ip_str[16];//Ŀ��ip��ַ

	//���ԴMAC��ַ
	sprintf(src_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->srcMac.byte0,
		csv_format->srcMac.byte1,
		csv_format->srcMac.byte2,
		csv_format->srcMac.byte3,
		csv_format->srcMac.byte4,
		csv_format->srcMac.byte5);
	//���ԴIP��ַ
	sprintf(src_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->srcIP.byte0,
		csv_format->srcIP.byte1,
		csv_format->srcIP.byte2,
		csv_format->srcIP.byte3);
	//���Ŀ��MAC��ַ
	sprintf(des_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->desMac.byte0,
		csv_format->desMac.byte1,
		csv_format->desMac.byte2,
		csv_format->desMac.byte3,
		csv_format->desMac.byte4,
		csv_format->desMac.byte5);
	//���Ŀ��IP��ַ
	sprintf(des_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->desIP.byte0,
		csv_format->desIP.byte1,
		csv_format->desIP.byte2,
		csv_format->desIP.byte3);

	char result[100];
	//��������ַ���
	sprintf(result, "%s,%s,%s,%s,%s,%d",
		timestr,
		src_mac_str,
		src_ip_str,
		des_mac_str,
		des_ip_str,
		csv_format->len);

	return result;
}


//����ͳ��
void add_alarm_flow(MAC_ADDR* mac_addr, IP_ADDR* ip_addr, int flow) {
	//��������
	if (GetTickCount64() - last_sec >= 1000) {
		for (int i = 0; i < flow_alarm_list->length; ++i) {
			(flow_alarm_list->HEAD + i)->total = 0;
		}
		last_sec = GetTickCount64();
	}

	//����ͳ��
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

	//����������ֵ�澯
	for (int i = 0; i < flow_alarm_list->length; ++i) {
		if ((flow_alarm_list->HEAD + i)->total >= LIMIT) {
			printf("%02X-%02X-%02X-%02X-%02X-%02X,%3d:%3d:%3d:%3d������������ֵ��\n",
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

//����ͳ��
void add_recv_flow(MAC_ADDR* mac_addr, IP_ADDR* ip_addr, int flow) {
	//����ͳ��
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

	//ͳ�����
	if ((GetTickCount64() - last_recv_output) >= STATISTIC_TIME) {
		printf("\nͳ�����Բ�ͬ MAC �� IP ��ַ��ͨ�����ݳ���:\n");
		for (int i = 0; i < flow_recv_list->length; ++i) {
			printf("Mac Address :%02X-%02X-%02X-%02X-%02X-%02X, IP Address:%3d:%3d:%3d:%3d, ͨ�����ݳ���:%d\n",
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

//����ͳ��
void add_send_flow(MAC_ADDR* mac_addr, IP_ADDR* ip_addr, int flow) {
	//����ͳ��
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



	//ͳ�����
	if ((GetTickCount64() - last_send_output) >= STATISTIC_TIME) {
		printf("\nͳ�Ʒ�����ͬ MAC �� IP ��ַ��ͨ�����ݳ���:\n");
		for (int i = 0; i < flow_send_list->length; ++i) {
			printf("Mac Address :%02X-%02X-%02X-%02X-%02X-%02X,IP Address:%3d:%3d:%3d:%3d, ͨ�����ݳ���:%d\n",
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

//�����¼�
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	(VOID)(param);
	struct CSV_FORMAT* csv = pkt_to_csv(header, pkt_data);
	add_alarm_flow(&csv->srcMac, &csv->srcIP, csv->len);
	add_recv_flow(&csv->desMac, &csv->desIP, csv->len);
	add_send_flow(&csv->srcMac, &csv->srcIP, csv->len);

	char output[100];
	strcpy(output, CSVFORMAT_to_str(csv));
	printf("%s\n", output);//�������Ļ
	fprintf(fp, "%s\n", output);//������ļ�
}


//������
int main() {
	//���ļ�
	fp = fopen(CSV_FILE_PATH, "w");

	//��ʼ������ͳ��
	//���������
	if ((flow_alarm_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_alarm_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_alarm_list->length = 0;

	//�������ͱ�
	if ((flow_recv_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_recv_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_recv_list->length = 0;

	//�������ձ�
	if ((flow_send_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_send_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_send_list->length = 0;

	//�豸ѡ��
	pcap_if_t* alldevs = getAllDevs();//��ȡ�豸�б�
	int DevsCount = printAllDevs();//����豸�б�

	if (DevsCount == 0) {
		printf("\n����δ����Winpcap\n");
		return -1;
	}

	pcap_if_t* current_dev = selectDev(DevsCount);//ѡ���豸
	//��ȡ���
	pcap_t* handle = getHandle(current_dev);

	//��������
	u_int netmask;
	if (current_dev->addresses != NULL)//��ǰ�豸��ַ��Ϊ����ȡ����
		netmask = ((struct sockaddr_in*)(current_dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;//�����豸��C����̫�������У�����Ϊ0xFFFFFF

	//������
	setfilter(handle, netmask);

	//����׼��
	printf("��ʼ����:%s\n", current_dev->description);
	pcap_freealldevs(alldevs);//�ͷ��豸�б�
	last_sec = GetTickCount64();
	last_recv_output = GetTickCount64();
	last_send_output = GetTickCount64();

	//��ʼ����
	pcap_loop(handle, 0, packet_handler, NULL);

	return 0;

}