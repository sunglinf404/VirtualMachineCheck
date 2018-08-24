#include "StdAfx.h"
#include "GetHostDiskInfo.h"


GetHostDiskInfo::GetHostDiskInfo(void)
{
	m_ParentDevice=NULL;//初始化主机磁盘句柄
}


GetHostDiskInfo::~GetHostDiskInfo(void)
{
	if (NULL != m_ParentDevice)
	{
		(void)CloseHandle(m_ParentDevice);//释放主机磁盘句柄
		m_ParentDevice = NULL;
	}
	
	


}

bool GetHostDiskInfo::UnicodeToZifu(UCHAR* Source_Unico, string& fileList, DWORD Size)
{
	wchar_t *toasiclls = new wchar_t[Size/2+1];
	if (NULL == toasiclls)
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "UnicodeToZifu::new::分配toasiclls内存失败!");
		return false;
	}
	memset(toasiclls,0,Size+2);
	char *str = (char*)malloc(Size+2);
	if (NULL == str)
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "UnicodeToZifu::malloc::分配str内存失败!");
		delete toasiclls;
		toasiclls = NULL;
		return false;
	}
	memset(str,0,Size+2);
	for (DWORD nl = 0; nl < Size; nl += 2)
	{
		toasiclls[nl/2] = Source_Unico[nl+1]<<8 | Source_Unico[nl];
	}

	int nRet=WideCharToMultiByte(CP_OEMCP, 0, toasiclls, -1, str, (Size+2), NULL, NULL); 
	if(nRet<=0)  
	{  
		CFuncs::WriteLogInfo(SLT_ERROR, "Unicode_To_Zifu::WideCharToMultiByte::转换失败失败!");
		free(str);
		str = NULL;
		delete toasiclls;
		toasiclls = NULL;
		return false;
	}  
	else  
	{  
		bool strbool = true;
		for (DWORD i = 0;i < Size; i++)
		{
			if (str[i] == 0)
			{
				fileList.append(str, i);
				strbool = false;
				//printf("%s\n",str);
				break;
			}
		}
		if (strbool)
		{
			fileList.append(str, Size);
		}

	}   

	free(str);
	str = NULL;
	delete toasiclls;
	toasiclls = NULL;
	return true;
}

bool  GetHostDiskInfo::ReadOnce(HANDLE hDevice, UCHAR* Buffer, WORD SIZE, DWORD *BackBytesCount)
{
	BOOL bRet = FALSE;
	if (SIZE<=512)
	{
		bRet = ReadFile(hDevice, Buffer, SECTOR_SIZE, BackBytesCount, NULL);
		if(!bRet)
		{		
			CFuncs::WriteLogInfo(SLT_ERROR, "ReadFile::读取失败!");
			return false;	
		}
	}
	else
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "ReadFile::超出字节大小,最大只能是512");


		return false;
	}
	return true;
}
bool  GetHostDiskInfo::ReadSQData(HANDLE hDevice, UCHAR* Buffer, DWORD SIZE, DWORD64 addr, DWORD *BackBytesCount)
{
	LARGE_INTEGER LiAddr = {0};	
	LiAddr.QuadPart=addr;
	DWORD dwError = 0;

	BOOL bRet = SetFilePointerEx(hDevice, LiAddr, NULL,FILE_BEGIN);
	if(!bRet)
	{

		dwError = GetLastError();
		CFuncs::WriteLogInfo(SLT_ERROR, _T("ReadSQData::SetFilePointerEx失败!,\
										   错误返回码: dwError = %d"), dwError);
		return false;	
	}
	bRet = ReadFile(hDevice, Buffer, SIZE, BackBytesCount, NULL);
	if(!bRet)
	{
		dwError = GetLastError();
		CFuncs::WriteLogInfo(SLT_ERROR, _T("ReadSQData::ReadFile失败!,\
										   错误返回码: dwError = %d"), dwError);					
		return false;	
	}

	return true;
}

bool  GetHostDiskInfo::GetMbrStartAddr(HANDLE hDevice, vector<DWORD64>& start_sq, UCHAR *ReadSectorBuffer, DWORD64 *LiAddr,DWORD *PtitionIdetifi)
{
	LMBR_Heads MBR = NULL;
	DWORD BackBytesCount = NULL;

	if(!ReadSQData(hDevice, ReadSectorBuffer, SECTOR_SIZE, (*LiAddr), &BackBytesCount))
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "GetMbrStartAddr::ReadSQData读取失败!,地址是%llu",(*LiAddr));
		return false;
	}
	for (int i = 0; i < 64; i += 16)
	{
		MBR = (LMBR_Heads)&ReadSectorBuffer[446 + i];				
		if (MBR->_MBR_Partition_Type == 0x05 || MBR->_MBR_Partition_Type == 0x0f)
		{
			if (ReadSectorBuffer[0] == 0 && ReadSectorBuffer[1] == 0 && ReadSectorBuffer[2] == 0 && ReadSectorBuffer[3] == 0)
			{				
				(*LiAddr) = ((*LiAddr) + ((DWORD64)MBR->_MBR_Sec_pre_pa) * SECTOR_SIZE);				
				GetMbrStartAddr(hDevice, start_sq, &ReadSectorBuffer[0], LiAddr,PtitionIdetifi);
			} 
			else
			{							
				(*LiAddr) = ((DWORD64)(MBR->_MBR_Sec_pre_pa) * SECTOR_SIZE);							
				GetMbrStartAddr(hDevice, start_sq, &ReadSectorBuffer[0], LiAddr,PtitionIdetifi);
			}
		} 
		else if (MBR->_MBR_Partition_Type == 0x00)
		{
			return true;
		}
		else if (MBR->_MBR_Partition_Type == 0x07)
		{
			if (ReadSectorBuffer[0] == 0 && ReadSectorBuffer[1] == 0 && ReadSectorBuffer[2] == 0 && ReadSectorBuffer[3] == 0)
			{				
				(*PtitionIdetifi)++;
				start_sq.push_back(*PtitionIdetifi);
				start_sq.push_back((MBR->_MBR_Sec_pre_pa + (*LiAddr) / SECTOR_SIZE));  			
			}
			else
			{
				(*PtitionIdetifi)++;
				start_sq.push_back(*PtitionIdetifi);
				start_sq.push_back(MBR->_MBR_Sec_pre_pa); 		
			}
		}
	}
	return true;
}

bool  GetHostDiskInfo::GetHostStartNTFSAddr(HANDLE hDevice, vector<DWORD64>& start_sq, UCHAR *ReadSectorBuffer)
{
	BOOL  BRet = FALSE;
	bool bRet = false;
	DWORD dwFileSize = NULL;
	DWORD BackBytesCount = NULL;
	DWORD SectorNum = NULL;
	DWORD64 LiAddr = NULL;
	LGPT_Heads GptHead = NULL;
	bool bReads = true;
	LGPT_FB_TABLE GptTable = NULL;

	DWORD partitiontype = NULL;
	DWORD LayoutSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(DRIVE_LAYOUT_INFORMATION_EX) * 150;
	PDRIVE_LAYOUT_INFORMATION_EX  LpDlie = (PDRIVE_LAYOUT_INFORMATION_EX)malloc(LayoutSize);
	if(NULL != LpDlie)
	{
		BRet = DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, LpDlie, LayoutSize, &BackBytesCount, NULL);
		if (BRet)
		{
			CFuncs::WriteLogInfo(SLT_INFORMATION, "分区数量%lu", LpDlie->PartitionCount);
			partitiontype = LpDlie->PartitionStyle;
			switch(partitiontype)
			{
			case 0:
				CFuncs::WriteLogInfo(SLT_INFORMATION, "分区类型是MBR");

				break;
			case 1:
				CFuncs::WriteLogInfo(SLT_INFORMATION, "分区类型是GPT");

				break;
			case 2:
				CFuncs::WriteLogInfo(SLT_INFORMATION, "Partition not formatted in either of the recognized formats—MBR or GPT");

				return true;
			}
		}
		else 
		{
			CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr DeviceIoControl 获取分区数量失败， errorId = %d", GetLastError());	
			free(LpDlie);
			LpDlie = NULL;
			return false;
		}
	}
	else
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr LpDlie calloc分配获取磁盘信息内存失败， errorId = %d", GetLastError());
		return false;
	}

	free(LpDlie);
	LpDlie = NULL;

	dwFileSize = GetFileSize(hDevice, NULL);
	CFuncs::WriteLogInfo(SLT_INFORMATION, "GetHostNtfsStartAddr GetFileSize 磁盘总大小是%lu", dwFileSize);

	bRet = ReadSQData(hDevice, ReadSectorBuffer, SECTOR_SIZE, 0, &BackBytesCount);	
	if(!bRet)
	{			
		CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr ReadSQData::读取第0扇区，获取MBR或GPT信息失败!");
		return false;	
	}

	while(SectorNum < 50)
	{
		if(ReadSectorBuffer[510] == 0x55 && ReadSectorBuffer[511] == 0xAA)
		{
			if(partitiontype == 0)
			{
				LiAddr = SectorNum * SECTOR_SIZE;
				CFuncs::WriteLogInfo(SLT_INFORMATION, "读取到MBR磁盘的MBR区域");


			}else if (partitiontype == 1)
			{

				CFuncs::WriteLogInfo(SLT_INFORMATION, "读取到GPT磁盘的保护MBR区域");
				SectorNum++;
				BRet = ReadFile(hDevice, ReadSectorBuffer, SECTOR_SIZE, &BackBytesCount, NULL);
				if(!BRet)
				{		
					
					CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr : ReadFile::读取MBR保护区域下一扇区失败!");
					return false;	
				}
			}
			break;
		}
		BRet = ReadFile(hDevice, ReadSectorBuffer, SECTOR_SIZE, &BackBytesCount, NULL);
		if(!BRet)
		{		
			
			CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr : ReadFile::读取MBR保护区域下一扇区失败!");
			return false;	
		}

		SectorNum++;
	}
	if(partitiontype == 0)
	{
		DWORD PititionIdetifi = NULL;
		if (!GetMbrStartAddr(hDevice, start_sq, &ReadSectorBuffer[0], &LiAddr, &PititionIdetifi))
		{
			
			CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr GetMbrStartAddr 寻找MBR起始扇区失败!!");
			return false;
		}
		else
		{
			CFuncs::WriteLogInfo(SLT_INFORMATION, "成功找到MBR分区,一共%d个分区", start_sq.size()/2);
		}

	}
	else if (partitiontype == 1)
	{
		DWORD GptIdentif = NULL;
		GptHead = (LGPT_Heads)&ReadSectorBuffer[0];
		if (GptHead->_Singed_name == 0x5452415020494645)
		{
			CFuncs::WriteLogInfo(SLT_INFORMATION, "这是GPT头部");

		}
		else
		{
			
			CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr 这个扇区不是GPT头部!!");
			return false;
		}
		GptHead = NULL;

		while(bReads)
		{
			BRet = ReadFile(hDevice, ReadSectorBuffer, SECTOR_SIZE, &BackBytesCount, NULL);
			if(!BRet)
			{		
				
				CFuncs::WriteLogInfo(SLT_ERROR, "GetHostNtfsStartAddr :ReadFile::读取GPT信息失败!");
				return false;	
			}

			SectorNum++;
			GptTable = (LGPT_FB_TABLE)&ReadSectorBuffer[0];
			for (int i = 0; (GptTable->_GUID_TYPE[0] != 0) && (i < 4); i++)
			{
				GptIdentif++;
				if (GptTable->_GUID_TYPE[0] == 0x4433b9e5ebd0a0a2)
				{
					start_sq.push_back(GptIdentif);
					start_sq.push_back(GptTable->_FB_Start_SQ);
				}
				if (i < 3)
				{
					GptTable++;
				}
			}
			if (GptTable->_FB_Start_SQ == 0)
			{
				
				CFuncs::WriteLogInfo(SLT_INFORMATION, "GPT列表结束");
				bReads =  false;
			}
		}
		GptTable = NULL;
		CFuncs::WriteLogInfo(SLT_INFORMATION, "一共读取了GPT分区%d个",start_sq.size()/2);

	}

	

	return true;
}

bool GetHostDiskInfo::InitHostDisk(void)
{
	DWORD dwError=NULL;
	/************************************************************************/
	/* 分配内存                                                                     */
	/************************************************************************/
	UCHAR *PatitionBuffer = NULL;
	PatitionBuffer = (UCHAR*)malloc(FILE_SECTOR_SIZE + SECTOR_SIZE);
	if (NULL == PatitionBuffer)
	{
		dwError=GetLastError();
		CFuncs::WriteLogInfo(SLT_ERROR, _T("InitHostDisk中PatitionBuffer=(UCHAR*)malloc(4096)分配内存失败!,\
										   错误返回码: dwError = %d"), dwError);
		return false;
	}
	/*初始化内存*/

	memset(PatitionBuffer, 0, FILE_SECTOR_SIZE + SECTOR_SIZE);
	/************************************************************************/
	/* 得到主机磁盘0句柄                                                                     */
	/************************************************************************/
	m_ParentDevice = CreateFile(_T("\\\\.\\PhysicalDrive0"),//这里注意，这个只是一个磁盘，程序需要兼容更多磁盘!!!!!
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (m_ParentDevice == INVALID_HANDLE_VALUE) 
	{
		dwError=GetLastError();
		CFuncs::WriteLogInfo(SLT_ERROR, _T("m_ParentDevice = CreateFile获取\\\\.\\PhysicalDrive0磁盘句柄失败!,\
										   错误返回码: dwError = %d"), dwError);
		free(PatitionBuffer);
		PatitionBuffer=NULL;
		return false;
	}
	/************************************************************************/
	/* 获得各个MBR或GPT分区起始地址                                                                     */
	/************************************************************************/
	if (!GetHostStartNTFSAddr(m_ParentDevice, m_vHostStarPartition, PatitionBuffer))
	{		
		CFuncs::WriteLogInfo(SLT_ERROR, _T("GET_MAIN_FB_START_SQ::读取分区信息失败!"));
		free(PatitionBuffer);
		PatitionBuffer=NULL;
		return false;
	} 

	free(PatitionBuffer);
	PatitionBuffer=NULL;
	return true;
}
