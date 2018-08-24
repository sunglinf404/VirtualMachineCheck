// test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "../Common/Funcs.h"
#include <iostream>
#include <map>
#include <vector>
#include <windows.h>
using namespace std;

typedef bool (*PFCallbackVirtualMachine)( const char* virtualFilePath, const char* virtualName);
typedef bool(*PFCallbackVirtualInternet)(const char* virtualFilePath, const char* virtualName, 
	const char* recorvyFilePath, int cdsType, const char* checkPath, const char* szTime, const char* szDomain, 
	const char* szAction, const char* szTitle, const char* name, const char* process);
typedef int (*PFVMwareVmadkForensics)(const int magic, const char* checkExt,const char* virtualFileDir,const char* CheckvirtualFileDir, PFCallbackVirtualMachine VirtualFile);
typedef int (*PVmwareInternetRecordCheck)(const int magic, const char* recordFilePath, const char* virtualFileDir, PFCallbackVirtualInternet VirtualRecord);
#define VL_MAGIC_NUMBER (0x23E72DAC)

bool virfile(const char* vitualpaths, const char* virName)
{
	CFuncs::WriteLogInfo(SLT_INFORMATION, "vitualpaths = %s, virName = %s", vitualpaths, virName);

	return true;
}
bool Rvirfile(const char* virtualPath, const char* virtualFilePath, const char* virtualName, 
	const char* recorvyFilePath, int cdsType, const char* checkPath, const char* szTime, const char* szDomain, 
	const char* szAction, const char* szTitle, const char* name, const char* process)
{
	CFuncs::WriteLogInfo(SLT_INFORMATION, "hostpaths = %s, vitualpaths = %s, virName = %s,  recorvyFilePath = %s"
		, virtualPath, virtualFilePath, virtualName,  recorvyFilePath);
	CFuncs::WriteLogInfo(SLT_INFORMATION, "cdsType = %d, checkPath = %s, szTime = %s, szDomain = %s, szAction = %s, \
										  szTitle = %s, name =%s, process = %s", cdsType, checkPath, szTime, szDomain, szAction, szTitle, name, process);


	return true;
}
int _tmain(int argc, _TCHAR* argv[])
{
	HINSTANCE m_Vmadkchek = ::LoadLibrary("VirtualMachineCheck.dll");
	if (NULL == m_Vmadkchek)
	{
		printf("错误:%d\n",GetLastError());
	}
	PFVMwareVmadkForensics Vmadkchek=(PFVMwareVmadkForensics)::GetProcAddress(m_Vmadkchek,"VirtualCheck");
	if (NULL == Vmadkchek)
	{
		printf("错误:%d\n",GetLastError());
	}
	int Imagic = VL_MAGIC_NUMBER;
	char *checkfileName = ".doc;.pdf";
	char *filedir = "d:\\d\\";
	char *virtualFile = "D:\\vhd\\test.vhd";
	if(!Vmadkchek(Imagic,checkfileName,filedir, virtualFile,&virfile))
	{
		printf("失败\n");
	}
	/*PVmwareInternetRecordCheck Recordcheck = (PVmwareInternetRecordCheck)::GetProcAddress(m_Vmadkchek, "VirtualInternetRecordCheck");
	if (NULL == Recordcheck)
	{
		return -1;
	}
	int Imagic = VL_MAGIC_NUMBER;*/
	//char *recordpath = "FileRecord,win7:AppData\\Roaming\\Microsoft\\Windows\\Recent\\";
	//char *recordpath = "360,win7:AppData\\Roaming\\360se6\\User Data\\Default\\History;FileRecord,win7:AppData\\Roaming\\Microsoft\\Windows\\Recent\\;chrome,win7:AppData\\Local\\Google\\Chrome\\User Data\\Default\\History";
	//char *recordpath = "regedit,win7:Windows:\\System32\\config\\SOFTWARE";
	//char *filedir="d:\\ddd\\";
	/*if (!Recordcheck(Imagic, recordpath, filedir, &Rvirfile))
	{
		return -1;
	}*/
	return 0;
}

