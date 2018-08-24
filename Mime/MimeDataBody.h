#pragma once

#include <vector>
#include <cstdio>
#include <sstream>
#include <cstring>
#include "MimeDataHeader.h"
#include "MimeBoundary.h"
#include "MimeCommon.h"
#include "../Common/Funcs.h"
#include "../Common/Exception.h"


//using std::vector;

typedef void (*WriteFileFuncPointer)(const string &fileName, const char *buf, int len, string &newFileName, size_t time);

struct AttachData
{
	uint32 fileSize;    //文件大小
	string fileName;	//原始文件名
	string filePath;	//存储后的文件名
};

//处理Mime主体数据类
class CMimeDataBody
{
public:
	CMimeDataBody(CMimeBuffer* pMimebuffer);
	~CMimeDataBody(void);
	/********************************************
	//函数功能：
	//		解析Mime主体数据
	//参数：
	//		content -- 主体数据
	//		header -- 解析后的Mime头部数据
	*********************************************/
	void HandleMimeDataBody(const char *content, size_t len, const CMimeBoundary &boundary);

	void HandleMimeDataBody(const char *content, size_t len, const CMimeBoundary &boundary, const char* savePath);

	void clearMimeDataBody();

	string getDataContent()	const	{return dataContent;}

	void InitAtthPath(const string &filePath);
	void InitAtthTag(const string &tag);
	void InitWriteFilePointer(WriteFileFuncPointer fpWritePointer);
	void InitCurrentTime(size_t currTime);
private:
	/*******************************************
	//函数功能;
	//		解析复合媒体类型multipart中子类型为mixed的数据
	//参数：
	//		str -- 主体数据
	//		boundary -- 头部数据中的边界界定线
	********************************************/
	void multipartMixed(const char *str, int len, const string &boundary);

	/********************************************
	//函数功能;
	//		解析复合媒体类型multipart中子类型为alternative的数据
	//参数：
	//		str -- 主体数据
	//		boundary -- 头部数据中的边界界定线		
	********************************************/
	void multipartAlternative(const char *str, size_t len, const string &boundary);
	
	void multipartAlternative(const char *str, size_t len, const string &boundary, const char* savePath);

	/*****************************************
	//函数功能：
	//		解析复合媒体中包含的离散媒体类型
	//参数：
	//		boundary -- 离散媒体类型的全部数据
	*****************************************/
	//void boundaryHandler(const Boundary &boundary);

	/*****************************************
	//函数功能;
	//		解析为离散媒体类型的Mime主体数据
	//参数：
	//		content -- Mime主体数据
	//		header -- Mime头部数据
	*****************************************/
	void discreptionTypeHandle(const char *content, size_t len, const CMimeBoundary &boundary);
		
	void discreptionTypeHandle(const char *content, size_t len, const CMimeBoundary &boundary, const char* savePath);

	/****************************************
	//函数功能：
	//		写附件内容
	//参数：
	//		filename -- 附件文件名
	//		buf -- 附件内容
	//		len -- 附件长度
	****************************************/
	void writeAtthFile(const string &filename, const char *buf, int len);
	
	void writeAtthFile(const string &filename, const char *buf, int len, const char* savePath);

	string renameAtthFile(const string &filename);
public:
	vector<AttachData> atthList;//附件名列表
private:
	CMimeBuffer* m_MimeBuffer;  //编码转换内存

	string dataContent;			//Mime邮件正文
	string atthPath;			//附件路径
	string atthTag;				//附件名标识 eg: POP3, SMTP
	size_t time;				//时间
	WriteFileFuncPointer fpWriteFilePointer;	//写附件文件指针
};

