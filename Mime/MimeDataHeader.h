#pragma once


#include <vector>
#include <sstream>
#include "MimeBoundary.h"
#include "../Common/Funcs.h"
#include "../Common/Exception.h"

using std::vector;

//处理Mime头部数据类
class CMimeDataHeader
{
private:
	string from;					//发件人
	string to;						//收件人
	string cc;						//抄送
	string bcc;						//密送
	string subject;					//主题
	//string contentType;			//媒体类型
	//string contentEncoder;		//编码方式
	//string boundary;				//边界分界线
	//string charSet;				//字符集
	string date;					//日期

	//2011-07-12
	//添加RCPT TO字段的收件人列表
	vector<string> rcptToList;
	//2011-07-12

	CMimeBuffer* m_MimeBuffer;      //编码转换内存

	string handleDate(const string &date);
	//void handleContentType(const string &value);
	void handleHeader(const string &content);
	//2011-07-12
	//将rcptTolist中的收件人以“；”连接
	string GetToFromRcptToList();
	//2011-07-12
public:
	CMimeDataHeader(CMimeBuffer* pMimebuffer);
	~CMimeDataHeader(void);
public:
	CMimeBoundary boundary;

	/***************************************
	//函数功能：
	//		初始化Mime数据头部
	//参数：
	//		str -- Mime头部数据
	***************************************/
	bool initMimeDataHeader(const char *src, size_t len);

	void clearMimeDataHeader();


	string getFrom() const		{return from;}
	string getTo() const		{return to;}
	string getCc() const		{return cc;}
	string getBcc()	const		{return bcc;}
	string getSubject() const	{return subject;}
	//string getContentType()	{return contentType;}
	//string getContentEncoder(){return contentEncoder;}
	//string getBoundary()		{return boundary;}
	//string getCharSet()		{return charSet;}
	string getDate() const		{return date;}
};

