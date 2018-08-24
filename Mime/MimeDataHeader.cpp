#include "stdafx.h"
#include "MimeDataHeader.h"

CMimeDataHeader::CMimeDataHeader(CMimeBuffer* pMimebuffer):boundary(pMimebuffer)
{
	m_MimeBuffer = pMimebuffer;
}

CMimeDataHeader::~CMimeDataHeader(void)
{

}

//由于字段值中也可以包含结束标志，如Content_Type字段。
//故采用反向查找下一个开始标志之间的结束标志来获取相关的
//字段字及其值。
bool CMimeDataHeader::initMimeDataHeader(const char *src, size_t len)
{
	char* pBegin = NULL;
	char* pIndex = NULL;
	char* pEnd = NULL;
	char* pEndEx = NULL;
	char* pTmp = NULL;
	string body;
	bool LoopFlag = true;
	int headerLength = 0;
	size_t offset = 0;
	bool isMimeEndFlagEx = false;
	try
	{
		pBegin = (char *)src;
		pIndex = CMimeCommon::memfind(pBegin, len, MimeBeginFlag.c_str(), MimeBeginFlag.size());		//查找第一个开始标识
		if(pIndex == NULL)
		{
			return false;
		}

		while(LoopFlag)
		{
			isMimeEndFlagEx = false;
			pTmp = pIndex + MimeBeginFlag.size();   //字段值Value的开始标识
			offset = pTmp - src;
			pIndex = CMimeCommon::memfind(pTmp, len - offset, MimeBeginFlag.c_str(), MimeBeginFlag.size());	//查找下一个开始标识
			if(pIndex == NULL)
			{
				offset = pBegin - src;
				body = string(pBegin, len - offset);
				LoopFlag = false;
			}
			else
			{
				offset = pIndex - src;
				pEnd = CMimeCommon::memrfind(src, offset, MimeEndFlag.c_str(), MimeEndFlag.size());  //反向查找结束标识
				pEndEx = CMimeCommon::memrfind(src, offset, MimeEndFlagEx.c_str(), MimeEndFlagEx.size());  //反向查找结束标识
				if(NULL == pEnd && NULL == pEndEx)
				{
						continue;
				}
				else
				{
					if(NULL == pEnd && NULL != pEndEx)
					{
						pEnd = pEndEx;
						isMimeEndFlagEx = true;
					}

					if(pEnd - pTmp < 0)		//结束标识小于字段值的开始标识，该结束并不是真正的结束标识
					{
						continue;
					}
					else
					{
						body = string(pBegin, pEnd - pBegin);		//找到结束标识，获取key_value对，如：From：hanxin110000@sina.com
						if(isMimeEndFlagEx)
						{
							pBegin = pEnd + MimeEndFlagEx.size();				//更新key的开始位置
						}
						else
						{
							pBegin = pEnd + MimeEndFlag.size();				//更新key的开始位置
						}
					}
				}
			}
			handleHeader(body);			//分析key_vaue对，解析其中的key与value
		}
	}
	catch(const exception &err)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"InitMimeDataHeader 出现异常：%s.", err.what());
		return false;
	}
	catch(...)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"InitMimeDataHeader 出现未知异常。");
		return false;
	}
	return true;
}

void CMimeDataHeader::handleHeader(const string &content)
{
	string key;
	string value;
	size_t index = 0;

	index = content.find(MimeBeginFlag);
	if(index == string::npos)
	{
		return;
	}
	key = content.substr(0, index);		//获取key
	size_t tmp = key.find(MimeEndFlag);		//去掉key中结束标识
	if(tmp != string::npos)
	{
		key = key.substr(tmp + MimeEndFlag.size());	
	}
	size_t tmpIndex = index + MimeBeginFlag.size();
	if((tmpIndex!= content.size()) && content[tmpIndex] == ' ')
	{
		tmpIndex++;		//去掉value中的di一个空格
	}
	value = content.substr(tmpIndex, content.size() - tmpIndex);
	//存储相关字段值
	if(key == MimeFrom)
	{
		from = CMimeCommon::mimeDecoder(value,m_MimeBuffer);
	}
	else if(key == MimeTo)
	{
		to = CMimeCommon::mimeDecoder(value,m_MimeBuffer);
		//2011-07-12
		//若收件人为空，就用rcptToList填充
		if(to.size() == 0)
		{
			to = GetToFromRcptToList();
		}
		//2011-07-12
	}
	else if(key == MimeCc)
	{
		cc = CMimeCommon::mimeDecoder(value,m_MimeBuffer);
	}
	else if(key == MimeBcc)
	{
		bcc = CMimeCommon::mimeDecoder(value,m_MimeBuffer);
	}
	else if(key == MimeSubject)
	{
		subject = CMimeCommon::mimeDecoder(value,m_MimeBuffer);
	}
	else if(key == MimeDate)
	{
		try
		{
			date = handleDate(value);
		}
		catch(...)
		{
			date = "";
		}
	}
	else if(key == MimeContentType)		//此处未处理“Content-type”的非正常情况
	{
		//contentType = value;
		//handleContentType(value);
		boundary.setContentType(value);
		boundary.handleContentType();

	}
	else if(key == MimeContentEncoder)
	{
		//contentEncoder = value;
		boundary.setContentEncoder(value);
	}
	else if(key == MimeContentDispostion)
	{
		boundary.setContentDisposition(value);
		boundary.handleContentDisposition();
	}
	//2011-07-12
	else if(key == MimeRcptTo)
	{
		size_t index = 0;
		index = value.rfind("DATA");
		if(index != string::npos)
		{
			value = value.substr(0, index);		//去掉RCPT中的"DATA"
		}
		rcptToList.push_back(value);
	}
	//2011-07-12
}

string CMimeDataHeader::GetToFromRcptToList()
{
	string result = "";
	for(size_t i = 0; i < rcptToList.size(); i++)
	{
		result += rcptToList[i];
		if(i != rcptToList.size() - 1)
		{
			result += ";";
		}
	}
	return result;
}

void CMimeDataHeader::clearMimeDataHeader()
{
	date.clear();
	from.clear();
	to.clear();
	cc.clear();
	bcc.clear();
	subject.clear();
	//contentType.clear();
	//contentEncoder.clear();
	//charSet.clear();
	boundary.clear();
}

string CMimeDataHeader::handleDate(const std::string &date)
{
	if(date.empty())
	{
		return "";
	}
	static char *month[12] = {"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};
	
	string result;
	int index = 0;
	int begin = 0;
	int size = 0;
	vector<string> list;
	bool flag = true;
	while(flag)
	{
		index = static_cast<int>(date.find(" ", begin));
		if(index == string::npos)
		{
			index = static_cast<int>(date.size());
			flag = false;
		}
		list.push_back(date.substr(begin, index - begin));
		begin = index + static_cast<int>(strlen(" "));
	}
	if(!list.size())
	{
		return ""; 
	}
	vector<string>::iterator iter = list.begin();
	size = list.size();
	if(size < 3 || size == 3)
	{
		for(int j = 1; j < size; j++)
		{
			result.append(*iter);
			if(j == size -1)
			{
				return result;
			}
			result.append(" ");
			*iter++;
		}
		return *iter;
	}
	iter += 3;
	result += *iter--;
	result += "-";
	for(int i = 0; i < 12; i++)
	{
		if(CMimeCommon::lowerToUpper(*iter) == month[i])
		{
			index = i + 1;
			break;
		}
	}
	stringstream ss;
	ss << index;
	result += ss.str();
	result += "-";
	iter--;
	result += *iter;
	result += " ";
	iter += 3;
	result += *iter;
	return result;
}
