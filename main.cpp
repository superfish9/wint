//////////////////////////////////////////////////////////////
//author : superfish
//date : 2015/12/12
//name : main.cpp
//thanks : yunshu
//////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "wint.h"

//程序入口
int main(int argc, char *argv[])
{
	char filePath[MAX_PATH] = {0}; //程序当前路径
	SERVICE_TABLE_ENTRY serviceTable[2];
	serviceTable[0].lpServiceName = SERVICE_NAME;
	serviceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	serviceTable[1].lpServiceName = NULL;
	serviceTable[1].lpServiceProc = NULL;
	
	GetModuleFileName(NULL, filePath, MAX_PATH);
	
	#ifdef DEBUG
        LogToFile("Call main\n");
    #endif
	
	if(argc == 2 && (!stricmp(argv[1], "-install"))){
		if(ServiceInstall(filePath) != TRUE){
			printf("Install service error\n");
			return -1;
		}
		printf("Install service successful\n");
	}else if(argc == 2 && (!stricmp(argv[1], "-unstall"))){
		if(ServiceUnstall(SERVICE_NAME) != TRUE){
			printf("Unstall service error\n");
			return -1;
		}
		printf("Unstall service successful\n");
	}else{
		if(!StartServiceCtrlDispatcher(serviceTable)){ //注册服务函数
			#ifdef DEBUG
                char tmp[256] = {0};
                sprintf(tmp, "Main StartServiceCtrlDispatcher error: %d\n", GetLastError());
                LogToFile(tmp);
            #endif
			printf("Main StartServiceCtrlDispatcher error: %d\n", GetLastError());
		}
		
		#ifdef DEBUG
		    LogToFile("Main StartServiceCtrlDispatcher successful\n");
		#endif
		printf("Main StartServiceCtrlDispatcher successful\n");
	}
	
	return 0;
}
