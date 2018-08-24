// VirtualMachineCheck.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "VirtualMachineCheck.h"



VIRTUALMACHINECHECK_API int VirtualCheck(const int magic, const char* checkExt,const char* virtualFileDir,const char* CheckvirtualFileDir, PFCallbackVirtualMachine VirtualFile)
{
	CFuncs::Init();
	bool bRet = false;
	if(VL_MAGIC_NUMBER != magic)
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "VirtualCheck 传入magic的值错误");
		return RVT_MAGIC;
	}

	string strVirtualDir = string(virtualFileDir);
	if('\\' != strVirtualDir[strVirtualDir.length() - 1])
	{
		strVirtualDir.append("\\");
	}
	if(!CFuncs::DirectoryExists(strVirtualDir.c_str()))
	{
		CreateDirectory(strVirtualDir.c_str(), NULL);
	}

	GetVirtualMachineInfo *pVMware = new GetVirtualMachineInfo();
	bRet = pVMware->VirtualFileCheckFuc(checkExt, strVirtualDir.c_str(), CheckvirtualFileDir, VirtualFile);
	if(!bRet)
	{
		delete pVMware;
		pVMware = NULL;
		return RVT_FALSE;
	}
	delete pVMware;
	pVMware = NULL;

	return RVT_TRUE;
}
VIRTUALMACHINECHECK_API int VirtualInternetRecordCheck(const int magic, const char* recordFilePath,const char* CheckvirtualFileDir, const char* virtualFileDir
	, PFCallbackVirtualInternetRecord VirtualRecord)
{
	CFuncs::Init();
	bool bRet = false;
	if(VL_MAGIC_NUMBER != magic)
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "VirtualInternetRecordCheck 传入magic的值错误");
		return RVT_MAGIC;
	}

	string strVirtualDir = string(virtualFileDir);
	if('\\' != strVirtualDir[strVirtualDir.length() - 1])
	{
		strVirtualDir.append("\\");
	}
	if(!CFuncs::DirectoryExists(strVirtualDir.c_str()))
	{
		CreateDirectory(strVirtualDir.c_str(), NULL);
	}
	GetVirtualMachineInfo *RecordCheck = new GetVirtualMachineInfo();
	bRet = RecordCheck->VirtualInternetCheeckFuc(recordFilePath, virtualFileDir, CheckvirtualFileDir, VirtualRecord);

	if(!bRet)
	{
		delete RecordCheck;
		RecordCheck = NULL;
		return RVT_FALSE;
	}
	delete RecordCheck;
	RecordCheck = NULL;
	return RVT_TRUE;
}
