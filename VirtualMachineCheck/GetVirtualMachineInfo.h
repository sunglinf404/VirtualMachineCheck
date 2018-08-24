#pragma once
#include "gethostdiskinfo.h"
#include "../Common/Funcs.h"
#include "../Mime/UrlConver.h"
#include "VirtualMachineBrowserRecord.h"
typedef bool (*PFCallbackVirtualMachine)(const char* virtualFilePath, const char* virtualName);

class GetVirtualMachineInfo :
	public GetHostDiskInfo
{
public:
	GetVirtualMachineInfo(void);
	~GetVirtualMachineInfo(void);
private:

	CVirtualMachineBrowserRecord* m_BrowserRecord;
private:

	bool GetcheckfileName(const char* checkExt, vector<string> &checkfilename);

	bool GetcheckVirtualFilePath(const char* CheckvirtualFileDir, vector<string> &VmdkParentMftBuff, string &VhdParentMftBuff
		, string &VboxParentMftBuff);
	//VMware虚拟机函数
	bool GetPititionName(vector<char>&chkdsk, vector<DWORD64>&dwDiskNumber);

	bool  GetMFTAddr(DWORD64 start_sq,vector<LONG64>& HVStarMFTAddr,vector<DWORD64>& HVStarMFTLen,UCHAR *HostPatitionCuNum
		, UCHAR *PatitionBuffer,bool HostOrVirtual);

	bool GetHostFileRecordAndDataRun(UCHAR *CacheBuff,DWORD64 hostpatition,LONG64 StartMftAddr,UCHAR HostCuNum,
		DWORD ReferNum, vector<string> lookforFileName,vector<string> &VmdkPathMftRefer, vector<string> &VhdPathMftRefer
		, vector<string> &VBoxPathMftRefer);

	bool VMwareFileCheck(vector<string> VMwareMftFileName, vector<string> checkfilename, const char* virtualFileDir, PFCallbackVirtualMachine VirtualFile);

	bool GetVirtualNumber(vector<string> ParentMftBuff, vector<DWORD>&VirtualNumber);

	bool GetHostFileNameAndPath(DWORD64 HostStartNTFSaddr,vector<LONG64> StartMFTaddr,vector<DWORD64> StartMFTaddrLen,UCHAR HostCuNumber
		,string ParentMFT, string &NamePathBuffer, char chkdk);

	bool  GetVirtualFileName(map<DWORD, vector<string>> &VirtualFileInfo, vector<string> VMwareMftFileName);

	bool  GetConfigInformation(map<DWORD, string> &DestBuff, UCHAR *SoursBuff
		, DWORD FileSize, DWORD *NameNum, string fPath);

	bool  GetVmdkInformation(vector<string> &DestData,UCHAR *SoursBuff, DWORD DataTotalNum
		, DWORD FileNumber, string fPath, map<DWORD, string> VirtualConfigFileInfo);

	bool GetVirtualNTSFAddr(map<DWORD, vector<string>> VirtualName,  DWORD VirtualNumber, vector<DWORD64> &v_VirtualNTFSStart, int VmdkfileType);

	bool GetChildDiskNTFSAddr(vector<string> VirtualName, vector<DWORD64> &v_VirtualStartaddr, int VmdkfileType);

	bool VMwareAddressConversion(vector<string> VirtualName, DWORD64 *backAddr, DWORD64 changeAddr, DWORD64 VmdkFiletotalsize
		, DWORD *FileNum, DWORD64 Grain_size, DWORD64 GrainNumber, DWORD64 GrainListOff, DWORD *LeftSector, int VmdkfileType, DWORD Catalogoff);

	bool VMwareReadData(string VirtualFileName, UCHAR *PatitionAddrBuffer, DWORD LeftSector, DWORD64 ReadAddr, DWORD ReadSize);

	bool Find_virtu_GPT(vector<string> VirtualName, UCHAR *CacenBuff, vector<DWORD64>& VirtualStartaddr, DWORD64 VmdkFileTatolSize
		, DWORD64 GrainSize, DWORD64 GrainNumber, DWORD64 GrainListOff, int VmdkfileType, DWORD Catalogoff);

	bool  Find_virtu_Mbr(vector<string> VirtualName, UCHAR *CacenBuff, vector<DWORD64>& VirtualStartaddr, DWORD64 VmdkFileTatolSize
		, DWORD64 GrainSize, DWORD64 GrainNumber, DWORD64 GrainListOff, DWORD64 *VmdkChangeAddr, int VmdkfileType, DWORD Catalogoff);

	bool GetVirtualMFTAddr(map<DWORD, vector<string>> VirtualName,  DWORD VirtualNumber, DWORD64 *VirMFTStartAddr
		, DWORD64 VirtualStartNTFSAddr, UCHAR* m_VirtualCuNum, int VmdkfileType);

	bool GetChildDiskMFTAddr( vector<string> VirtualName, DWORD64 *VirMFTStartAddr, UCHAR *m_VirtualCuNum, DWORD64 VirtualStartNTFSAddr
		, int VmdkfileType);

	bool GetVirtualAllMFTStartAddr(map<DWORD, vector<string>> VirtualName, DWORD VirtualNumber,  DWORD64 VirMFTStartAddr
		, DWORD64 VirtualStartNTFSAddr, UCHAR m_VirtualCuNum, vector<LONG64> &v_VirtualStartMftAddr, vector<DWORD64> &v_VirtualStartMftLen
		, int VmdkfileType);

	bool GetChildDiskAllMFTStartAddr(UCHAR m_VirtualCuNum, vector<LONG64> &v_VirtualStartMftAddr, vector<DWORD64> &v_VirtualStartMftLen
		, DWORD64 StartVirtualMFT, DWORD64 StartVirtualNTFS, vector<string> VirtualName, int VmdkfileType);

	bool GetVirtualFileAddr(DWORD64 VirtualStartNTFS, LONG64 VirStartMftRfAddr, UCHAR *CacheBuff,  vector<DWORD> &H20FileRefer,
		UCHAR VirtualCuNum, vector<string> checkfilename, DWORD *ParentMft, vector<LONG64> &Fileh80datarun, vector<DWORD> &Fileh80datalen, 
		string &Fileh80data, DWORD RereferNumber, string &FileName, DWORD64 *filerealsize, DWORD64 VmdkFiletotalsize, DWORD64 Grain_size, DWORD64 GrainNumber,
		DWORD64 GrainListOff, vector<string> VirtualName, int VmdkfileType, DWORD Catalogoff);

	bool  GetVirtualH20FileReferH80Addr(UCHAR *CacenBuff, vector<LONG64> &H80datarun, vector<DWORD> &H80datarunlen
		, string &h80data, DWORD64 *FileRealSize);

	bool  VirtualWriteLargeFile(UCHAR VirCuNum,vector<LONG64> FileH80Addr, vector <DWORD> FileH80Len, DWORD64 VirStartNTFSAddr
		, const wchar_t *PreserFileName, DWORD64 filerealSize, DWORD64 VmdkFiletotalsize, DWORD64 Grain_size, DWORD64 GrainNumber,
		DWORD64 GrainListOff, vector<string> VirtualName, int VmdkfileType, DWORD Catalogoff);

	bool GetVirtualFilePath( DWORD64 VirtualNtfs, vector<LONG64> VirtualStartMFTaddr, vector<DWORD64> VirtualStartMFTaddrLen
		, UCHAR VirtualCuNum, DWORD ParentMFT, string& VirtualFilePath, string FileName, DWORD64 VmdkFiletotalsize, DWORD64 Grain_size, DWORD64 GrainNumber,
		DWORD64 GrainListOff, vector<string> VirtualName, int VmdkfileType, DWORD Catalogoff);

	bool VirtualWriteLitteFile(string &BuffH80, const wchar_t *FileDir);

	//VHD虚拟机函数
	bool GetVhdHeadInfor(HANDLE VhdDrive, DWORD *batentrynum, DWORD *BatOffset, DWORD *BatBlockSize, LONGLONG *VHDUUID, wchar_t *NtfsIncreVhdPathName);

	bool VhdFileCheck(string VhdMftFileName, vector<string> checkfilename, const char* virtualFileDir, PFCallbackVirtualMachine VirtualFile);

	bool JudgeVHDFile(string VhdName, UCHAR *vhdtype);

	void  GetDwodSize(UCHAR *source,DWORD *dest);

	void  GetDwodtoDwod(DWORD *source,DWORD *dest);

	bool VhdNameChange(LONGLONG VHDUUID, UCHAR *VhdHeadBuff, wchar_t *NtfsIncreVhdPathName);

	bool GetVHDVirtualNTFSStartAddr(LONGLONG *VhdUUID, vector<DWORD64> &VirtualNTFSStartaddr, wchar_t * IncreVhdPathName, HANDLE VhdDrive
		, string VHDSalfPath, UCHAR *vhdtype);

	bool GetParentVhdPatitionAddr(HANDLE h_VhdDrive,UCHAR *CacheFileRecoBuffer,vector<DWORD64>&VirtualStartaddr, UCHAR vhdtype
		, LONGLONG *VhdUUID,  wchar_t *NtfsIncreVhdPathName);

	bool CacheParentVhdTable(HANDLE h_drive,UCHAR *CacheBuff,DWORD BatOffset,DWORD BatSize);

	bool ParentVhdOneAddrChange(DWORD64 ChangeAddr,DWORD *VhdTable,DWORD BatBlockSize,DWORD64 *BackAddr,DWORD BatEntryMaxNumber);

	bool FindParentVHDVirtual_GPT(HANDLE h_drive,DWORD *BatEntry,DWORD BatEntryTotalNum,DWORD BatBlockSize
		,UCHAR *CacheBuff,vector<DWORD64>& VirtualStartaddr, UCHAR vhdtype);

	bool FindParentVHDVirtual_Mbr(HANDLE h_drive,DWORD64 *VhdChangeAddr,DWORD *BatEntry,DWORD BatEntryTotalNum,DWORD BatBlockSize,
		UCHAR *CacheBuff,vector<DWORD64>& VirtualStartaddr, UCHAR vhdtype);

	bool GetDifferNTFSStartAddr(HANDLE VhdDrive, vector<DWORD64> &VirNTFSStartAddr, LONGLONG *VhdUUID,  wchar_t * IncreVhdPathName, UCHAR vhdtype);

	bool GetVirtualStartMftAddr(HANDLE VhdDrive, LONGLONG *VhdUUID, DWORD64 *VirtualMftStartaddr, wchar_t * IncreVhdPathName, UCHAR* m_VirtualCuNum
		, DWORD64 StarNTFSAddr, string VHDSalfPath, UCHAR *vhdtype);

	bool GetIncrementMFTStartAddr(HANDLE p_drive,UCHAR *CacheBuff,DWORD64 *VirtualStartMftAddr,UCHAR *VirtualCuNum
		,DWORD64 VirtualStartNTFS, UCHAR vhdtype, LONGLONG *VhdUUID, wchar_t * IncreVhdPathName);

	bool GetBasicMftAddr(HANDLE VhdDrive ,LONGLONG* VhdUUID, wchar_t *IncreVhdPathName, DWORD64 VirtualStartNTFS, UCHAR *VirtualCuNum
		, DWORD64 *StartMftAddr, UCHAR vhdtype);

	bool VirGetAllMftAddr(HANDLE VhdDrive, LONGLONG *VhdUUID, wchar_t *IncreVhdPathName, DWORD64 StartNtfsAddr, DWORD64 StartMftAddr
		, UCHAR VirtualCuNum, vector<LONG64> &v_VirtualStartMftAddr, vector<DWORD64> &v_VirtualStartMftLen, string VHDSalfPath, UCHAR *vhdtype);

	bool GetIncrementAllMFTStartAddr(HANDLE p_drive, UCHAR *CacheBuff,DWORD64 StartNTFSAddr,DWORD64 StratMFTAddr,UCHAR VirtualCuNum
		,vector<LONG64> &v_VirtualStartMftAddr,vector<DWORD64> &v_VirtualStartMftLen, UCHAR VHDtype, LONGLONG *VhdUUID, wchar_t *IncreVhdPathName);

	bool GetBasicAllMftAddr(HANDLE VhdDrive ,LONGLONG *VhdUUID, wchar_t* IncreVhdPathName, DWORD64 VirtualStartNTFS, DWORD64 StartMftAddr
		, UCHAR VirtualCuNum, UCHAR *CacheBuff, vector<LONG64> &v_VirtualStartMftAddr,vector<DWORD64> &v_VirtualStartMftLen, UCHAR VHDtype);

	bool GetVHDVirtualFileAddr(HANDLE VhdDrive ,DWORD64 VirtualStartNTFS, LONG64 VirStartMftRfAddr, DWORD *BatEntry
		, DWORD BatEntryMaxNumber, DWORD BatBlockSize, UCHAR *CacheBuff, vector<DWORD> &H20FileRefer, UCHAR VirtualCuNum, vector<string> checkfilename
		, DWORD *ParentMft, vector<LONG64>&fileh80datarun, vector<DWORD>&fileh80datalen, string &fileh80data, DWORD Rerefer, string &FileName
		, DWORD64 *FileRealSize, UCHAR VHDtype);

	bool VHDWriteLargeFile(HANDLE VhdhDrive, vector<LONG64> FileH80Addr, vector<DWORD> FileH80Len, UCHAR VirtualCuNum, DWORD *BatEntry
		, DWORD BatEntryMaxNumber, DWORD BatBlockSize, UCHAR *WriteBuff , const wchar_t *FileDir, DWORD64 VirPatition
		, DWORD64 fileRealSize, UCHAR Vhdtype);

	bool GetVHDFileNameAndPath(DWORD64 VirtualNtfs, vector<LONG64> VirtualStartMFTaddr, vector<DWORD64> VirtualStartMFTaddrLen
		, UCHAR VirtualCuNum, DWORD ParentMFT, UCHAR *CacheBuffer, string& VirtualFilePath, DWORD *BatEntry, DWORD BatEntryMaxNumber, DWORD BatBlockSize
		, string FileName, HANDLE VhdDrive, UCHAR Vhdtype);
	//VBox虚拟机函数

	bool VboxFileCheck(string VBoxMftFileName, vector<string> checkfilename, const char* virtualFileDir
		, PFCallbackVirtualMachine VirtualFile);

	bool GetVboxInformation(map<DWORD, string> &VdiFileInfo, string VboxPath, string vdipath, int *VBoxFileType);

	bool  ReadSQCharData(HANDLE hDevice, char* Buffer, DWORD SIZE, DWORD64 addr, DWORD *BackBytesCount);

	bool GetVdiInformation(map<DWORD, string> &VdiFileInfo, string VdiBuff, string vdipath, int *VBoxFileType);

	bool DwordStringToHex(DWORD *outdword, string Instring);

	bool GetVdiNTFSStartAddr(DWORD *VdiUUID, map<DWORD, string> VdiFileInfo, vector<DWORD64> &VdiNTFSStartAddr);

	bool GetVdiHeadInformation(HANDLE hdrive,DWORD *VdiBatAddr,DWORD *VdiDataAddr,DWORD *BatSingleSize, DWORD *ParentUUID);

	bool GetVdiChildNTFSInfomation(HANDLE hDrive, DWORD BatListSize, DWORD VdiBatStartAddr, DWORD VdiBatSingleSize, 
		vector<DWORD64> &VirtualStartaddr, DWORD VdiDataStartAddr);

	bool GetVdiBatListInformation(HANDLE hDrive, UCHAR *VdiBatBuff, DWORD VdiBatStartAddr, DWORD BatListSize);

	bool VdiOneAddrChange(DWORD64 VdiChangeAddr, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize, DWORD64 *VdiBackAddr
		, DWORD BatListSize, DWORD VdiDataStartAddr);

	bool FindVirtualVdiGPTInfo(HANDLE h_drive, UCHAR *CacheBuff, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize, DWORD BatListSize,
		vector<DWORD64> &VirtualStartaddr, DWORD VdiDataStartAddr);

	bool FindVirtualVdiMBRInfo(HANDLE h_drive, UCHAR *CacheBuff, DWORD64 *VdiChangeAddr, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize,
		DWORD BatListSize, vector<DWORD64> &VirtualStartaddr, DWORD VdiDataStartAddr);

	bool GetVdiStartMftAddr(DWORD *VdiUUID, map<DWORD, string> VdiFileInfo, DWORD64 VirtulPatition, DWORD64 *VirtualStartMft
		, UCHAR *m_VirtualCuNum);

	bool GetVdiChildMftStartAddr(HANDLE hDrive, DWORD BatListSize, DWORD VdiBatStartAddr, DWORD VdiBatSingleSize, DWORD64 VirtulPatition
		, DWORD64 *VirtualStartMft, UCHAR *m_VirtualCuNum, DWORD VdiDataStartAddr);

	bool GetVdiAllMftAddr(DWORD *VdiUUID, map<DWORD, string> VdiFileInfo, DWORD64 VirtulPatition, DWORD64 VirtualStartMft
		, UCHAR m_VirtualCuNum,  vector<LONG64> &v_VirtualStartMftAddr, vector<DWORD64> &v_VirtualStartMftLen);

	bool GetVdiChildAllMftAddr(HANDLE hDrive, DWORD BatListSize, DWORD VdiBatStartAddr, DWORD VdiBatSingleSize, DWORD64 VirtulPatition
		, DWORD64 VirtualStartMft, UCHAR m_VirtualCuNum, vector<LONG64> &v_VirtualStartMftAddr, vector<DWORD64> &v_VirtualStartMftLen
		, DWORD VdiDataStartAddr);

	bool GetVboxVirtualFileAddr(HANDLE hDrive, DWORD64 VirtualStartPatition, DWORD64 VirStartMftRfAddr, UCHAR VirtualCuNum, DWORD Rerefer, UCHAR *VdiBatBuff
		, DWORD VdiBatSingleSize, DWORD BatListSize, UCHAR *CacheBuff, DWORD *ParentMft, string &FileName, vector<LONG64> &fileh80datarun, vector<DWORD> &fileh80datalen
		, string &fileh80data, vector<DWORD> &H20FileRefer, vector<string> checkfilename, DWORD VdiDataStartAddr, DWORD64 *fileRealSize);

	bool VirtualVdiWriteLargeFile(HANDLE hDrive, vector<LONG64> FileH80Addr, vector<DWORD> FileH80Len, UCHAR VirtualCuNum, UCHAR *VdiBatBuff
		, DWORD VdiBatSingleSize, DWORD BatListSize, char *WriteBuff ,const wchar_t *FileDir, DWORD VdiDataStartAddr, DWORD64 VirPatition
		, DWORD64 fileRealSize);

	bool GetVirtualVdiFileNameAndPath(HANDLE hDrive, string FileName, UCHAR *CacheBuffer, DWORD ParentMFT, vector<LONG64> VirtualStartMFTaddr
		, vector<DWORD64> VirtualStartMFTaddrLen, UCHAR VirtualCuNum, DWORD64 VirtualNtfs, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize, DWORD BatListSize
		, string& VirtualFilePath, DWORD VdiDataStartAddr);

	bool GetVboxVmdkInfomation(map<DWORD, vector<string>> &VboxVmdkInfo, map<DWORD, string>VdiFileInfo);

	bool GetVboxVmdkDescrip(char *descripBuff, vector<string> &vmdkname, DWORD *ParenUUID, string Vmdkpath);

	//分析VMDK
	bool AnalysisVmdkFile(map<DWORD, vector<string>> VMDKNameInfo, vector<string> checkfilename
		, const char* virtualFileDir, PFCallbackVirtualMachine VirtualFile);
	//上网记录函数


	bool AnalysisInterPath(map<string,map<string, string>> &PathAndName, const char *recordFilePath);
	
	bool GetVMwareInternetInfo(map<string,map<string, string>> PathAndName, vector<string> VMwareMftFileName, const char* virtualFileDir
		, PFCallbackVirtualInternetRecord VirtualRecord);

	bool AnalysisVmdkFileInternet(map<string,map<string, string>> PathAndName, map<DWORD, vector<string>> VMDKNameInfo
		, const char* virtualFileDir, PFCallbackVirtualInternetRecord VirtualRecord);

	bool LookforVmdkInterFileRefer(DWORD64 VirtualStartNTFS, LONG64 VirStartMftRfAddr, DWORD64 VmdkFiletotalsize, UCHAR *CacheBuff, 
		UCHAR VirtualCuNum, DWORD RereferNumber, vector<LONG64> v_VirtualStartMFTaddr, vector<DWORD64> v_VirtualStartMFTaddrLen, vector<string> VirtualName
		, map<string, map<string, string>> PathName, int *PathFound, string &VirtualFilePath, DWORD *FileRefer, string &BrowerType, string &RecordFileName
		,  DWORD64 Grain_size, DWORD64 GrainNumber,DWORD64 GrainListOff,  int VmdkfileType, DWORD Catalogoff);

	bool GetIndexHeadInfo(DWORD *IndexMemberSize, DWORD *IndexRealSize, LONG64 HA0Addr, vector<string> VirtualName
		, DWORD64 VirNtfsAddr, UCHAR m_VirtualCuNum, DWORD64 VmdkFiletotalsize,  DWORD *IndexHeadSize, vector<UCHAR> &IndexUpdata,  DWORD64 Grain_size
		, DWORD64 GrainNumber,DWORD64 GrainListOff,  int VmdkfileType, DWORD Catalogoff);

	bool GetHA0FileRecordRefer( UCHAR m_VirtualCuNum, DWORD64 VmdkFiletotalsize, vector<string> VirtualName
		, DWORD64 VirNtfsAddr, vector<LONG64> HA0addr, vector<DWORD> HA0len, DWORD64 HA0RealSize, map<DWORD, string> &BrowerfileRefer
		,  DWORD64 Grain_size, DWORD64 GrainNumber,DWORD64 GrainListOff,  int VmdkfileType, DWORD Catalogoff);

	bool GetCatalogFileRefer(UCHAR *fileRecordBuff,  UCHAR m_VirtualCuNum, DWORD64 VmdkFiletotalsize, DWORD64 VirNtfsAddr
		, map<DWORD, string> &BrowerfileRefer,  DWORD64 Grain_size, DWORD64 GrainNumber,DWORD64 GrainListOff,  int VmdkfileType, DWORD Catalogoff
		, vector<string> VirtualName);

	bool ExtractingTheCatalogFile(DWORD64 VmdkFiletotalsize, DWORD64 VirtualStartNTFS, LONG64 VirStartMftRfAddr, UCHAR VirtualCuNum
		, DWORD Rerefer, vector<LONG64> v_VirtualStartMFTaddr, string RecordFileName, vector<DWORD64> v_VirtualStartMFTaddrLen, const char *virtualFileDir
		, DWORD64 Grain_size, DWORD64 GrainNumber,DWORD64 GrainListOff,  int VmdkfileType, DWORD Catalogoff, vector<string> VirtualName);

	bool GetInternetFileAddr(UCHAR *FilrRecordBuff, vector<DWORD> &RecordH20Refer, vector<LONG64> &FileH80Addr, vector<DWORD> &FileH80len, 
		string &FileH80Data, DWORD64 *FileRealSize, UCHAR VirtualCuNum,DWORD64 VmdkFiletotalsize, DWORD64 VirtualStartNTFS, DWORD64 Grain_size, DWORD64 GrainNumber,DWORD64 GrainListOff,  int VmdkfileType, DWORD Catalogoff
		, vector<string> VirtualName);

	bool VirtualInternetRecord( const char* virtualMachineRecordFilePath, const char* recordFilename,
		const char* browserType, const char* recoveryPath, PFCallbackVirtualInternetRecord VirtualRecord);

	bool VmdkExtractingFileRecordFile(DWORD64 VmdkFiletotalsize, DWORD64 VirtualStartNTFS, LONG64 VirStartMftRfAddr, UCHAR VirtualCuNum
		, DWORD Rerefer, vector<LONG64> v_VirtualStartMFTaddr, string RecordFileName, vector<DWORD64> v_VirtualStartMFTaddrLen, DWORD64 Grain_size
		, DWORD64 GrainNumber,DWORD64 GrainListOff,  int VmdkfileType, DWORD Catalogoff, vector<string> VirtualName, string &FileRecordLastVTM
		, string &FileRecordPath);

	bool ReadBigShortCuFileInfo(UCHAR VirCuNum,vector<LONG64> FileH80Addr, vector <DWORD> FileH80Len, DWORD64 VirStartNTFSAddr
		, DWORD64 filerealSize, DWORD64 VmdkFiletotalsize, DWORD64 Grain_size, DWORD64 GrainNumber,DWORD64 GrainListOff, vector<string> VirtualName
		, int VmdkfileType, DWORD Catalogoff, UCHAR *ReadBuff);

	bool GetShortCutFileDataInfo(UCHAR *ShortCutBuff, string &FileRecordLastVTM, string &FileRecordPath, DWORD64 filesize);

	bool FileRecordTimeChange(string &timestr, UCHAR *Timeymd, UCHAR *Timehms);

	//VBox上网记录分析函数

	bool GetVBoxInternetInfo(map<string,map<string, string>> PathAndName, string VBoxMftFileName, const char* virtualFileDir
		, PFCallbackVirtualInternetRecord VirtualRecord);

	bool VBoxFindRecordFile(HANDLE hDrive, DWORD64 VirtualStartPatition, DWORD64 VirStartMftRfAddr, UCHAR VirtualCuNum, DWORD Rerefer
		, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize, DWORD BatListSize, string &BrowerType, string &RecordFileName, int *PathFound, DWORD *FileRefer
		, UCHAR *CacheBuff, DWORD VdiDataStartAddr, map<string, map<string, string>> PathName, string &VirtualFilePath, vector<LONG64> v_VirtualStartMFTaddr
		, vector<DWORD64> v_VirtualStartMFTaddrLen);

	bool VBoxGetRecordFileAddr(HANDLE hDrive, DWORD64 *FileRealSize, UCHAR *FilrRecordBuff, vector<DWORD> &RecordH20Refer, UCHAR VirtualCuNum, DWORD64 VirtualStartPatition
		, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize, DWORD BatListSize, DWORD VdiDataStartAddr, vector<LONG64> &FileH80Addr, vector<DWORD> &FileH80len
		, string &FileH80Data);

	bool VBoxGetCatalogFileRefer(HANDLE hDrive, UCHAR *fileRecordBuff, map<DWORD, string> &BrowerfileRefer, UCHAR VirCuNum, DWORD64 VirtualPatition
		, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize, DWORD BatListSize, DWORD VdiDataStartAddr);

	bool VBoxGetHA0FileRecordRefer(HANDLE hDrive, vector<LONG64> HA0addr, vector<DWORD> HA0len, UCHAR m_VirtualCuNum, DWORD64 HA0RealSize, DWORD64 VirtualStartPatition
		, UCHAR *VdiBatBuff, DWORD VdiBatSingleSize, DWORD BatListSize, DWORD VdiDataStartAddr, map<DWORD, string> &BrowerfileRefer);

	bool VBoxGetIndexHeadInfo(HANDLE hDrive, DWORD64 VirtualStartPatition, LONG64 HA0Addr, UCHAR m_VirtualCuNum, UCHAR *VdiBatBuff
		, DWORD VdiBatSingleSize, DWORD BatListSize, DWORD VdiDataStartAddr, DWORD *IndexHeadSize, vector<UCHAR> &IndexUpdata, DWORD *IndexMemberSize, DWORD *IndexRealSize);

	bool VBoxExtractingTheCatalogFile(HANDLE hDrive, DWORD64 VirtualPatition, UCHAR *VirVdiBatBuff, DWORD VirBatSingleSize, DWORD VirBatBuffSize,
		vector<LONG64> v_VirtualStartMFTaddr, vector<DWORD64> v_VirtualStartMFTaddrLen, DWORD Rerefer, UCHAR VirtualCuNum, DWORD VirVdiDataAddr, string RecordFileName
		, const char *virtualFileDir);

	bool VBoxExtractingFileRecordFile(HANDLE hDrive, DWORD64 VirtualPatition, UCHAR *VirVdiBatBuff, DWORD VirBatSingleSize, DWORD VirBatBuffSize,
		vector<LONG64> v_VirtualStartMFTaddr, vector<DWORD64> v_VirtualStartMFTaddrLen, DWORD Rerefer, UCHAR VirtualCuNum, DWORD VirVdiDataAddr, string RecordFileName
		, string &FileRecordLastVTM, string &FileRecordPath);

	bool VboxReadBigShortCuFileInfo(UCHAR VirCuNum,vector<LONG64> FileH80Addr, vector <DWORD> FileH80Len
		, DWORD64 filerealSize, UCHAR *ReadBuff, HANDLE hDrive, DWORD64 VirtualPatition, UCHAR *VirVdiBatBuff, DWORD VirBatSingleSize, DWORD VirBatBuffSize
		, DWORD VirVdiDataAddr);

	bool  FileTimeConver(UCHAR* szFileTime, string& strTime);

public:
	bool  VirtualFileCheckFuc(const char* checkExt,const char* virtualFileDir,const char* CheckvirtualFileDir, PFCallbackVirtualMachine VirtualFile);

	bool VirtualInternetCheeckFuc(const char* recordFilePath, const char* virtualFileDir,const char* CheckvirtualFileDir, PFCallbackVirtualInternetRecord VirtualRecord);
};

