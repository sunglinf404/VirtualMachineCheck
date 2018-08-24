#include "StdAfx.h"
#include "VirtualMachineBrowserRecord.h"


CVirtualMachineBrowserRecord::CVirtualMachineBrowserRecord(void)
{
}


CVirtualMachineBrowserRecord::~CVirtualMachineBrowserRecord(void)
{
}

bool CVirtualMachineBrowserRecord::ChromeRecordFile(const char* virtualPath, const char* recordFilename, 
	const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExist(strNetRecdFile.c_str()))
	{
		return false;
	}

	char *dataPath = (LPSTR)strNetRecdFile.c_str();
	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char szVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			strTitle = (char *)tmpTitle;

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(szVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord( virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM, strSystemPath.c_str(), szVisitTime, (char*)url, Cache_Action.c_str(), 
				strTitle.c_str(), VL_Browser_GoogleChrome_NAME.c_str(), VL_Browser_GoogleChrome_PROCESS.c_str());

//#ifdef _DEBUG
//
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "Google上网记录:  checkPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), szVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), VL_Browser_GoogleChrome_NAME.c_str(),
//												  VL_Browser_GoogleChrome_PROCESS.c_str());	
//#endif

			memset(szVisitTime, 0, sizeof(szVisitTime));
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}

bool CVirtualMachineBrowserRecord::OperaRecordFile(const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExist(strNetRecdFile.c_str()))
	{
		return false;
	}

	char* dataPath = (LPSTR)strNetRecdFile.c_str();
	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char strVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}
	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			strTitle = (char *)tmpTitle;

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			strTitle = string((char *)tmpTitle);
			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord( virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM,  strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_Opera_NAME.c_str(), VL_Browser_Opera_PROCESS.c_str());
//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "欧朋上网记录: strSystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, url, Cache_Action.c_str(), strTitle.c_str(), VL_Browser_Opera_NAME.c_str(), VL_Browser_Opera_PROCESS.c_str());
//			memset(strVisitTime, 0, sizeof(strVisitTime));
//#endif
		}
	}
	//CFuncs::AppendBinaryFile(m_DataSave->m_FStream);
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;

}

bool CVirtualMachineBrowserRecord::SogouRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExist(strNetRecdFile.c_str()))
	{
		return false;
	}
	char* dataPath = (LPSTR)strNetRecdFile.c_str();
	vstring strTitle;
	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select id,title,last from UserRankUrl";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}
	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			const unsigned char* time = sqlite3_column_text(stmt, 2);

			strTitle = string((char *)tmpTitle);
			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			InternetRecord(virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM, strSystemPath.c_str(), (char*)time, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_Sogou_NAME.c_str(), VL_Browser_Sogou_PROCESS.c_str());
//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "搜狗上网记录: strSystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), (char*)time, url, Cache_Action.c_str(), strTitle.c_str(), 
//												  VL_Browser_Sogou_NAME.c_str(), VL_Browser_Sogou_PROCESS.c_str());
//#endif
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}

bool CVirtualMachineBrowserRecord::QQRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExist(strNetRecdFile.c_str()))
	{
		return false;
	}

	char* dataPath = (LPSTR)strNetRecdFile.c_str();
	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char strVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			strTitle = string((char *)tmpTitle);
			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord( virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM,  strSystemPath.c_str(), (char*)strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_QQ_NAME.c_str(), VL_Browser_QQ_PROCESS.c_str());

//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "QQ上网记录: strSystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, url, Cache_Action.c_str(), strTitle.c_str(), VL_Browser_QQ_NAME.c_str(), VL_Browser_QQ_PROCESS.c_str());
//			memset(strVisitTime, 0, sizeof(strVisitTime));
//#endif
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}


//360安全浏览器
bool CVirtualMachineBrowserRecord::QihuRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExists(strNetRecdFile.c_str()))
	{
		return false;
	}
	char* dataPath = (LPSTR)strNetRecdFile.c_str();

	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char strVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			strTitle = string((char*)tmpTitle);

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);


			InternetRecord(virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM,  strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_360_NAME.c_str(), VL_Browser_360_PROCESS.c_str());

		/*	CFuncs::WriteLogInfo(SLT_INFORMATION, "360上网记录: strSystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(),
												  VL_Browser_360_NAME.c_str(), VL_Browser_360_PROCESS.c_str());	*/

			memset(strVisitTime, 0, sizeof(strVisitTime));
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;

}

bool CVirtualMachineBrowserRecord::QihuChromeRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExists(strNetRecdFile.c_str()))
	{
		return false;
	}
	char* dataPath = (LPSTR)strNetRecdFile.c_str();

	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char strVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			strTitle = string((char*)tmpTitle);

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord(virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM, strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_360Chrome_NAME.c_str(), VL_Browser_360Chrome_PROCESS.c_str());
//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "360极速上网记录: strSystemPath = %s,  strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(),
//												  VL_Browser_360Chrome_NAME.c_str(), VL_Browser_360Chrome_PROCESS.c_str());	
//#endif
			memset(strVisitTime, 0, sizeof(strVisitTime));
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}

//UC浏览器
bool CVirtualMachineBrowserRecord::UCRecordFile(const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExists(strNetRecdFile.c_str()))
	{
		return false;
	}
	char* dataPath = (LPSTR)strNetRecdFile.c_str();

	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char strVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			strTitle = string((char*)tmpTitle);

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord( virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM,  strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_UC_NAME.c_str(), VL_Browser_UC_PROCESS.c_str());
//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "UC上网记录: strSystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, url, Cache_Action.c_str(), strTitle.c_str(), VL_Browser_UC_NAME.c_str(), VL_Browser_UC_PROCESS.c_str());
//			memset(strVisitTime, 0, sizeof(strVisitTime));
//#endif
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}

//猎豹浏览器
bool CVirtualMachineBrowserRecord::LiebaoRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExists(strNetRecdFile.c_str()))
	{
		return false;
	}

	char* dataPath = (LPSTR)strNetRecdFile.c_str();
	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char strVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			strTitle = string((char *)tmpTitle);
			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord(virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM, strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_Liebao_NAME.c_str(), VL_Browser_Liebao_PROCESS.c_str());
//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "猎豹上网记录: strSystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, url, Cache_Action.c_str(), strTitle.c_str(), VL_Browser_Liebao_NAME.c_str(), VL_Browser_Liebao_PROCESS.c_str());	
//			memset(strVisitTime, 0, sizeof(strVisitTime));
//#endif
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}


//2345王牌浏览器
bool CVirtualMachineBrowserRecord::Browser2345RecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (!CFuncs::FileExists(strNetRecdFile.c_str()))
	{
		return false;
	}

	char* dataPath = (LPSTR)strNetRecdFile.c_str();

	vstring strTitle;
	FILETIME fileTime;
	time_t tmpTime;
	struct tm localTime;
	char strVisitTime[20] = { 0 };

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_time from urls";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			strTitle = string((char*)tmpTitle);

			__int64 visitTime = sqlite3_column_int64(stmt, 2);
			visitTime = visitTime * 10;

			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			memset(&fileTime, 0, sizeof(fileTime));
			memset(&localTime, 0, sizeof(localTime));
			memcpy((void *)&fileTime, (void *)&visitTime, 8);
			tmpTime = CCommon::FileTimeToTime_t(fileTime);
			localtime_s(&localTime, &tmpTime);

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord( virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM, strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_2345_NAME.c_str(), VL_Browser_2345_PROCESS.c_str());
//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "2345王牌上网记录: strSystemPath = %s strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(),
//												  VL_Browser_2345_NAME.c_str(), VL_Browser_2345_PROCESS.c_str());	
//#endif

			memset(strVisitTime, 0, sizeof(strVisitTime));
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}

//遨游浏览器
//bool CVirtualMachineBrowserRecord::MaxthonRecordDirectory(const char* browserType, const vstring& strNetRecdPath, vstring& strSystemPath, PFCallbackInternetRecord InternetRecord)
//{
//	if (strNetRecdPath.empty())
//	{
//		return false;
//	}
//	vstring tempPath = strNetRecdPath;
//	tempPath.append("*.*");
//	WIN32_FIND_DATA FindFileData;
//	HANDLE hFind = ::FindFirstFile(tempPath.c_str(), &FindFileData);
//	if (INVALID_HANDLE_VALUE == hFind)
//	{
//		return false;
//	}
//	while (::FindNextFile(hFind, &FindFileData))
//	{
//		if (strcmp(FindFileData.cFileName, ".") == 0 || strcmp(FindFileData.cFileName, "..") == 0)
//		{
//			continue;
//		}
//		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
//		{
//			vstring strRecdFile = FindFileData.cFileName;
//			vstring strExt = CFuncs::ParseFileExt(strRecdFile.c_str());
//			if (strExt.empty())
//			{
//				strRecdFile = strNetRecdPath + strRecdFile + Maxthon_Record;
//				if (!CFuncs::FileExist(strRecdFile.c_str()))
//				{
//					FindClose(hFind);  
//					return false;
//				}
//				/*			if (!ParseMaxthonRecordFile(strRecdFile, strSystemPath, InternetRecord))
//				{
//				CFuncs::WriteLogInfo(SLT_ERROR,_T("解析Maxthon浏览器的上网记录日志文件(%s)失败!"), strRecdFile);
//				FindClose(hFind);  
//				return false;
//				}*/
//			}
//		}
//	}
//	FindClose(hFind);  
//	return true;
//
//}

bool CVirtualMachineBrowserRecord::ParseMaxthonRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{

	if(!CFuncs::FileExist(strNetRecdFile))
	{
		return false;
	}

	char* dataPath = (LPSTR)strNetRecdFile.c_str();

	//加载动态库对Maxthon浏览器历史记录文件进行解密
	HINSTANCE hInst = LoadLibrary("SecretLib.dll");
	if (NULL == hInst)
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "加载SecretLib.dll失败!\n");
		return false;
	}
	PFDecryptMaxthon DecryptMaxthon = (PFDecryptMaxthon)GetProcAddress(hInst, "DecryptMaxthon");
	if (NULL == DecryptMaxthon)
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "加载SecretLib.dll函数DecryptMaxthon失败!\n");
		return false;
	}
	char* dst = "../Maxthon";
	if (!DecryptMaxthon(dataPath, dst))
	{
		return false;
	}

	vstring strTitle;
	char strVisitTime[20] = { 0 };
	struct tm localTime;
	memset(&localTime, 0, sizeof(localTime));

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,date from urlhistory where date <> 0";
	int rc = sqlite3_open(dst, &pDB);
	if (rc)
	{
		DeleteFile(dst);
		return false;
	}
	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			__int64 VisitTime = sqlite3_column_int64(stmt, 2);
			localtime_s(&localTime, &VisitTime);

			strTitle = string((char *)tmpTitle);
			wchar_t wsTemp[1024];
			int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
			wsTemp[length] = 0;
			char sTemp[1024 * 2];
			length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
			sTemp[length] = 0;
			strTitle = sTemp;

			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord( virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM, strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_Maxthon_NAME.c_str(), VL_Browser_Maxthon_PROCESS.c_str());
//#ifdef _DEBUG
//			CFuncs::WriteLogInfo(SLT_INFORMATION, "遨游上网记录: strSystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
//												  browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, url, Cache_Action.c_str(), strTitle.c_str(), VL_Browser_Maxthon_NAME.c_str(), VL_Browser_Maxthon_PROCESS.c_str());	
//			memset(strVisitTime, 0, sizeof(strVisitTime));
//#endif
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);
	DeleteFile(dst);
	return true;

}

//bool CVirtualMachineBrowserRecord::FirefoxRecordDirectory(const char* localPath, const char* virtualPath, const char* recordFilename, const vstring& strNetRecdDir, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
//{
//	if (strNetRecdDir.empty())
//	{
//		return false;
//	}
//	vstring tempPath = strNetRecdDir;
//	tempPath.append("*.*");
//	WIN32_FIND_DATA FindFileData;
//	HANDLE hFind = ::FindFirstFile(tempPath.c_str(), &FindFileData);
//	if (INVALID_HANDLE_VALUE == hFind)
//	{
//		return false;
//	}
//	while (::FindNextFile(hFind, &FindFileData))
//	{
//		if (strcmp(FindFileData.cFileName, ".") == 0 || strcmp(FindFileData.cFileName, "..") == 0)
//		{
//			continue;
//		}
//		if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
//		{
//			vstring strRecdFile = FindFileData.cFileName;
//			/*vstring strExt = CFuncs::ParseFileExt(strRecdFile.c_str());*/
//			if (0 == _stricmp(strRecdFile.c_str(), Firefox_Record.c_str()))
//			{
//				strRecdFile = strNetRecdDir + "\\" + Firefox_Record;
//				if (!CFuncs::FileExist(strRecdFile.c_str()))
//				{
//					FindClose(hFind);  
//					return false;
//				}
//				if (!ParseFirefoxRecordFile(localPath, virtualPath,  recordFilename,  strRecdFile,  strSystemPath, InternetRecord))
//				{
//					CFuncs::WriteLogInfo(SLT_ERROR,_T("解析Firefox浏览器的上网记录日志文件(%s)失败!"), strRecdFile);
//					FindClose(hFind);  
//					return false;
//				}
//			}
//		}
//	}
//	FindClose(hFind);  
//	return true;
//}

bool CVirtualMachineBrowserRecord::ParseFirefoxRecordFile( const char* virtualPath, const char* recordFilename, const vstring& strNetRecdFile, vstring& strSystemPath, PFCallbackVirtualInternetRecord InternetRecord)
{
	if (strNetRecdFile.empty())
	{
		return false;
	}

	char* dataPath = (LPSTR)strNetRecdFile.c_str();

	vstring strTitle;
	char tmpTime[11] = { 0 };
	char strVisitTime[20] = { 0 };
	__time64_t dwVistTime;
	struct tm localTime;
	memset(&localTime, 0, sizeof(localTime));

	sqlite3* pDB = NULL;
	sqlite3_stmt* stmt = NULL;
	const char* zTail;
	char* sql = "select url,title,last_visit_date from moz_places where last_visit_date not null";
	int rc = sqlite3_open(dataPath, &pDB);
	if (rc)
	{
		CFuncs::WriteLogInfo(SLT_ERROR, "打开Firefox历史记录失败:%s", dataPath);
		return false;
	}

	if (SQLITE_OK == sqlite3_prepare_v2(pDB, sql, -1, &stmt, &zTail))
	{
		while (SQLITE_ROW == sqlite3_step(stmt))
		{
			strTitle.clear();
			const unsigned char* url = sqlite3_column_text(stmt, 0);
			const unsigned char* tmpTitle = sqlite3_column_text(stmt, 1);
			const unsigned char* VisitTime = sqlite3_column_text(stmt, 2);

			memcpy(tmpTime, VisitTime, 10);
			dwVistTime = _atoi64(tmpTime);
			localtime_s(&localTime, &dwVistTime);

			if (NULL != tmpTitle)    //获得地址有可能为空,所以要判断
			{
				strTitle = string((char *)tmpTitle);
				wchar_t wsTemp[1024];
				int length = CCharsetConver::UTF8ToUnicode(strTitle.c_str(), (int)strTitle.length(), wsTemp, _countof(wsTemp) - 1);
				wsTemp[length] = 0;
				char sTemp[1024 * 2];
				length = CCharsetConver::UnicodeToGB2312(wsTemp, length, sTemp, _countof(sTemp) - 1);
				sTemp[length] = 0;
				strTitle = sTemp;
			}
			sprintf_s(strVisitTime, "%04d-%02d-%02d %02d:%02d:%02d", localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
				localTime.tm_hour, localTime.tm_min, localTime.tm_sec);

			InternetRecord( virtualPath, recordFilename, strNetRecdFile.c_str(), CCT_VM, strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(), 
				VL_Browser_Firefox_NAME.c_str(), VL_Browser_Firefox_PROCESS.c_str());
			/*#ifdef _DEBUG
			CFuncs::WriteLogInfo(SLT_INFORMATION, "Firefox上网记录: SystemPath = %s, strVisitTime = %s, url = %s, Action = %s, strTitle = %s,\
			browser = %s, process = %s", strSystemPath.c_str(), strVisitTime, (char*)url, Cache_Action.c_str(), strTitle.c_str(),
			VL_Browser_Firefox_NAME.c_str(), VL_Browser_Firefox_PROCESS.c_str());	
			#endif*/
		}
	}
	sqlite3_finalize(stmt);    //释放资源并关闭数据库
	sqlite3_close(pDB);

	return true;
}