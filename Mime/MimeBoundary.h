#pragma once

#include "MimeCommon.h"
#include "../Common/Funcs.h"
#include "../Common/Exception.h"

//
//处理边界界定线之间的所有数据（包括头部和主体）类
class CMimeBoundary
{
public:
	/**********************************
	//函数功能：
	//		解析数据
	//参数：
	//		str -- 要解析的数据
	***********************************/
	CMimeBoundary(CMimeBuffer* pMimebuffer);
	~CMimeBoundary(void);

	bool initBoundary(const char *src, int len);
	void handleBoundaryheader(const string &content);
	void handleContentType(void);
	void handleContentDisposition(void);
	void clear();

	void setContentType(const string &value)		{contentType = value;}
	void setContentDisposition(const string &value)	{contentDisposition = value;}
	void setBoundary(const string &value)			{boundary = value;}
	void setContentEncoder(const string &value)		{contentEncoder = value;}
	void setFileName(const string &value)			{filename = value;}
	void setContent(char *value)					{content = value;}
	void setContentLength(int length)				{contentLength = length;}
	void setCharSet(const string &value)			{charSet = value;}

	string getContentType()	const					{return contentType;}
	string getContentDisposition() const			{return contentDisposition;}
	string getBoundary() const						{return boundary;}
	string getContentEncoder() const				{return contentEncoder;}
	string getFileName() const						{return filename;}
	char *getContent()	const						{return content;}
	int getContentLength() const					{return contentLength;}
	string getCharSet()	const						{return charSet;}
private:
	string contentType;				//媒体类型
	string contentDisposition;		//内容处理方式
	string boundary;				//边界界定线
	string contentEncoder;			//编码方式
	string filename;				//附件名
	char*  content;					//主体数据
	int    contentLength;			//主体数据长度
	string charSet;					//字符集

	CMimeBuffer* m_MimeBuffer;      //编码转换内存
};
