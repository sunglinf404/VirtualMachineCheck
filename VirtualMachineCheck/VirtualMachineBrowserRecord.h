#pragma once

#include "../Common/Funcs.h"
#include "../Common/Exception.h"
#include "../Common/Common.h"
#include "../Sqlite3/dlsqlite3.h"
#include "../Mime/UrlConver.h"
//#include "BrowserRecordSave.h"

const vstring Firefox_Record			= "places.sqlite";
const vstring Maxthon_Record			= "\\History\\History.dat";

class CVirtualMachineBrowserRecord
{
public:
	CVirtualMachineBrowserRecord(void);
	~CVirtualMachineBrowserRecord(void);
public:
	//¹È¸èä¯ÀÀÆ÷
	bool ChromeRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//Å·Åó
	bool OperaRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//ËÑ¹·ä¯ÀÀÆ÷
	bool SogouRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//QQä¯ÀÀÆ÷
	bool QQRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//360°²È«ä¯ÀÀÆ÷
	bool QihuRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//360¼«ËÙä¯ÀÀÆ÷
	bool QihuChromeRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//UCä¯ÀÀÆ÷
	bool UCRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//ÁÔ±ªä¯ÀÀÆ÷
	bool LiebaoRecordFile(const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//2345ÍõÅÆä¯ÀÀÆ÷
	bool Browser2345RecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//åÛÓÎä¯ÀÀÆ÷
	//bool MaxthonRecordDirectory(const char* browserType, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackInternetRecord InternetRecord);

	bool ParseMaxthonRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	//»ðºüä¯ÀÀÆ÷
	//bool FirefoxRecordDirectory(const char* localPath, const char* virtualPath, const char* recordFilename, const vstring& strNetRecdDir, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

	bool ParseFirefoxRecordFile(const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord);

};

 