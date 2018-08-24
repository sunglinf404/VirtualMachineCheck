#include "StdAfx.h"
#include "MimeCommon.h"


CMimeCommon::CMimeCommon(void)
{

}


CMimeCommon::~CMimeCommon(void)
{

}

char* CMimeCommon::memchr_ex(const char *src, char c, size_t len)
{
	try
	{
		char *p1 = (char *)src;
		for(size_t i = 0;i < len; i++)
		{
			if(*p1 == c ) 
			{
				return p1;  
			}
			p1++;
		}
	}
	catch (...)
	{

	}
	return NULL;
}

//查找子串
char* CMimeCommon::memfind(const char *src, size_t srclen, const char *dst, size_t dstlen)
{
	try
	{
		char *p1 = (char *)src;
		char *p2 = NULL;
		size_t  offset = 0;
		size_t  plen = srclen - dstlen;
		if((src!=NULL) && (dst!=NULL)  && (srclen>0) && (dstlen>0) && (srclen>=dstlen))
		{
			p2 = memchr_ex(src,*dst,srclen-dstlen);
			while(p2)
			{
				if(memcmp(p2,dst,dstlen)==0)
				{
					break;
				}
				else
				{
					//计算偏移量
					p2++;
					offset =  (int)(p2 - p1);

					if (plen >= offset)
					{
						p2 = memchr_ex(p2,*dst,(plen -offset));
					}
					else
					{
						return NULL;
					}
				}
			}
		}
		return p2;
	}
	catch (...)
	{
		return NULL;
	}
}

char* CMimeCommon::memchr_rex(const char *src, char c, size_t len)
{
	try
	{
		char *p1 = (char *)src + len;
		for(size_t i = 0;i < len; i++)
		{
			if(*p1 == c ) 
			{
				return p1;  
			}
			p1--;
		}
	}
	catch (...)
	{

	}
	return NULL;
}

//反向查找子串
char* CMimeCommon::memrfind(const char *src, size_t srclen, const char *dst, size_t dstlen)
{
	try
	{
		char *p1 = (char *)src + srclen;
		char *p2 = NULL;
		size_t  offset = 0;
		size_t  plen = srclen - dstlen;
		if((src!=NULL)  && (dst!=NULL)  &&(srclen>0) && (dstlen>0) &&(srclen>=dstlen))
		{
			p2 = memchr_rex(src,*dst,plen);
			while(p2)
			{
				if(memcmp(p2,dst,dstlen)==0)
				{
					break;
				}
				else
				{
					//计算偏移量
					//p2--;
					offset =  (int)(p1 - p2 + 1);

					if (srclen >= offset)
					{
						p2 = memchr_rex(src,*dst,(srclen -offset));
					}
					else
					{
						return NULL;
					}
				}
			}
		}
		return p2;
	}
	catch (...)
	{
		return NULL;
	}
}

string CMimeCommon::upperToLower(const string &src)
{
	string result = src;
	for(int i = 0; i < static_cast<int>(result.size()); i++)
	{
		if((result[i] >= 'A') && (result[i] <= 'Z'))
		{
			result[i] = result[i] - 'A' + 'a';
		}
	}
	return result;
}


string CMimeCommon::lowerToUpper(const string &src)
{
	string result = src;
	for(int i = 0; i < static_cast<int>(result.size()); i++)
	{
		if((result[i] >= 'a') && (result[i] <= 'z'))
		{
			result[i] = result[i] - 'a' + 'A';
		}
	}
	return result;
}

/**********************************
函数功能：
	对形如"=?gbk?B?vNHEvsu5v6q3orDs?="字符串进行解码
参数:
	src -- 编码字符串
返回值：
	解码后的字符串
**********************************/
string CMimeCommon::mimeDecoder(const string& str, CMimeBuffer* pMimebuffer)
{
	int index = 0;
	int begin = 0, end = 0;
	string result, tmp(str);
	string charSet, key, content;

	if(pMimebuffer == NULL)
	{
		return "";
	}

	while((index = static_cast<int>(tmp.find(MimeEncoderBeginFlag, begin))) != string::npos)
	{
		//获取编码前的字符
		if(index != begin)
		{
			//暂时不去换行
			result += tmp.substr(begin, index - begin);			
		}
		begin = index + static_cast<int>(MimeEncoderBeginFlag.size());
		index = static_cast<int>(tmp.find(MimeEncoderFlag, begin));
		if(index == string::npos)
		{
			continue;
		}
		//获取字符串编码前的字符集
		charSet = tmp.substr(begin, index - begin);
		begin = index + static_cast<int>(MimeEncoderFlag.size());
		index = static_cast<int>(tmp.find(MimeEncoderFlag, begin));
		if(index == string::npos)
		{
			continue;
		}
		//获取编码方式
		key = tmp.substr(begin, index - begin);
		begin = index + static_cast<int>(MimeEncoderFlag.size());
		
		end = static_cast<int>(tmp.find(MimeEncoderEndFlag, begin));
		if(end == string::npos)
		{
			continue;
		}
		//获取实际编码字符串
		int len = 0;
		content = tmp.substr(begin, end -begin);
		memset(pMimebuffer->getDecodeBuffer(), 0, content.size() + 1);
		//编码方式为“B”时进行base64解码否则进行quoter_printer解码
		key = lowerToUpper(key);
		if(key == "B")
		{
			len= CBase64::Decode((uint8 *)(content.c_str()), static_cast<size_t>(content.size()), 
				(uint8 *)(pMimebuffer->getDecodeBuffer()), pMimebuffer->getDecodeBufferSize());
			if(len == -1)
			{
				CFuncs::WriteLogInfo(SLT_ERROR,"Base64解码错误:%s",content.c_str());
				return "";
			}
		}
		else if(key == "Q")
		{
			len = CCharsetConver::DecoderQuoterPrinter(content.c_str(), static_cast<int>(content.size()),
				pMimebuffer->getDecodeBuffer(), pMimebuffer->getDecodeBufferSize());
			if (len == -1)
			{
				CFuncs::WriteLogInfo(SLT_ERROR,"quoter_printer解码错误:%s",content.c_str());
				return "";
			}
		}
		//字符集为utf-8时进行utf-8到Ansi码转换
		if(upperToLower(charSet).find("utf-8") != string::npos)
		{
			len = CCharsetConver::UTF8ToUnicode(pMimebuffer->getDecodeBuffer(),len,
				pMimebuffer->getDecodeWideBuffer(),pMimebuffer->getDecodeWideBufferSize());
			len = CCharsetConver::UnicodeToANSI(pMimebuffer->getDecodeWideBuffer(),len,
				pMimebuffer->getDecodeBuffer(),pMimebuffer->getDecodeBufferSize());
		}
		else if(upperToLower(charSet).find("iso-2022-jp") != string::npos)
		{
			len = CCharsetConver::ISO2022JPToUnicode(pMimebuffer->getDecodeBuffer(),len,
				pMimebuffer->getDecodeWideBuffer(),pMimebuffer->getDecodeWideBufferSize());
			len = CCharsetConver::UnicodeToANSI(pMimebuffer->getDecodeWideBuffer(),len,
				pMimebuffer->getDecodeBuffer(),pMimebuffer->getDecodeBufferSize());
		}
		else if(upperToLower(charSet).find("big5") != string::npos)
		{
			len = CCharsetConver::BIG5ToUnicode(pMimebuffer->getDecodeBuffer(),len,
				pMimebuffer->getDecodeWideBuffer(),pMimebuffer->getDecodeWideBufferSize());
			len = CCharsetConver::UnicodeToGB2312(pMimebuffer->getDecodeWideBuffer(),len,
				pMimebuffer->getDecodeBuffer(),pMimebuffer->getDecodeBufferSize());
		}
		result.append(pMimebuffer->getDecodeBuffer());
		begin = end + static_cast<int>(MimeEncoderEndFlag.size());
		tmp = tmp.substr(begin, tmp.size() - begin);
		begin = 0;
	}
	result.append(tmp);
	return result;
}

string CMimeCommon::GetSessionID(const char* proto, const uint32 sip, const uint16 sport)
{
	char tmpBuf[1024 * 3];
	memset(tmpBuf, 0, sizeof(tmpBuf));
	sprintf_s(tmpBuf, _countof(tmpBuf),"%s_%u_%u_%s",proto,sip,sport,CFuncs::GetGUID().c_str());
	return string(tmpBuf);
}