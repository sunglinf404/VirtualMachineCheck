#include "StdAfx.h"
#include "CharsetConver.h"


CCharsetConver::CCharsetConver(void)
{
}


CCharsetConver::~CCharsetConver(void)
{
}

int CCharsetConver::ANSIToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}
	//转UNICODE
	int length = ::MultiByteToWideChar( CP_ACP, 0, src, -1, NULL, 0); 
	if(dstlen < (length + (int)sizeof(wchar_t)))
	{
		return -1;
	}
	length = ::MultiByteToWideChar( CP_ACP, 0, src, -1, dst, length); 
	return length;
}

int CCharsetConver::UnicodeToANSI(const wchar_t *src, int srclen, char *dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}
	int length = WideCharToMultiByte(CP_ACP, 0, src, srclen ,NULL, 0, NULL, NULL);
	if(dstlen < (length + (int)sizeof(char)))
	{
		return -1;
	}
	memset(dst, 0, dstlen);
	WideCharToMultiByte(CP_ACP, 0, src, srclen, dst, length, NULL, NULL);
	return length;
}

int CCharsetConver::UnicodeToGB2312(const wchar_t *src, int srclen, char *dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}
	int length = WideCharToMultiByte(936, 0, src, srclen, NULL, 0, NULL, NULL);
	if(length >= dstlen)
	{
		return -1;
	}
	memset(dst, 0, dstlen);
	WideCharToMultiByte(936, 0, src, srclen, dst, length, NULL, NULL);
	return length;
}

/****************************************
函数功能：
	将UTF-8码转换为Unicode码
参数：
	src -- UTF-8编码字符串
	dst -- Uncode编码 长度最好为src的3倍
返回值：
	-1失败
****************************************/
int CCharsetConver::UTF8ToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}
	int length = MultiByteToWideChar(CP_UTF8, 0, src, srclen, NULL, 0);
	if(dstlen < (length + (int)sizeof(wchar_t)))
	{
		return -1;
	}
	memset(dst, 0, dstlen);
	MultiByteToWideChar(CP_UTF8, 0, src, srclen, dst, length);
	return length;
}

int CCharsetConver::UTF8ToGB2312(const char *src, int srclen, wchar_t *wdst, int wdstlen,char *dst, int dstlen)
{
	int len = UTF8ToUnicode(src,srclen,wdst,wdstlen);
	len = UnicodeToGB2312(wdst,len,dst,dstlen);
	return len;
}

int CCharsetConver::ISO2022JPToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}

	int length = MultiByteToWideChar(50220, 0, src, srclen, NULL, NULL);
	if(length >= dstlen)
	{
		return -1;
	}
	memset(dst, 0, dstlen);
	MultiByteToWideChar(50220, 0, src, srclen, dst, length);
	
	return length;
}

int CCharsetConver::BIG5ToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}
	int length = MultiByteToWideChar(950, 0, src, srclen, NULL, NULL);
	if(length >= dstlen)
	{
		return -1;
	}
	memset(dst, 0, dstlen);
	MultiByteToWideChar(950, 0, src, srclen, dst, length);

	return length;
}

//抓换后的数据结果存放于dst中
int CCharsetConver::BIG5ToGB2312(char *src, int srclen, wchar_t *wdst, int wdstlen, char* dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}
	int length = BIG5ToUnicode(src,srclen,wdst,wdstlen);
	if(length == -1)
	{
		return -1;
	}
	length = UnicodeToGB2312(wdst,length,dst,dstlen);
	if(length == -1)
	{
		return -1;
	}
	return length;
}

//必须是BIG5已经转换为GB2312格式后才能进行翻译,如果数据是BIG5,请先调用BIG5ToGB2312函数再进行翻译
int CCharsetConver::BIG5TranslateGB2312(char *src, int srclen,char* dst, int dstlen)
{
	if(src == NULL && dst == NULL)
	{
		return -1;
	}
	LCID Locale = MAKELCID(MAKELANGID(LANG_CHINESE,SUBLANG_CHINESE_SIMPLIFIED),SORT_CHINESE_PRC);
	int length = LCMapString(Locale,LCMAP_SIMPLIFIED_CHINESE, src,srclen,NULL,0);
	if(length >= dstlen)
	{
		return -1;
	}
	length = LCMapString(Locale,LCMAP_SIMPLIFIED_CHINESE,src,srclen,dst,dstlen);
	return length;
}

int CCharsetConver::QuotedPrintableFlag(char ch)
{
	if((ch >= 'a') && (ch <= 'z'))
	{
		ch = ch - 'a' + 'A';
	}
	if((ch >= '0') && (ch <= '9'))
	{
		return ch - '0';
	}
	else if((ch >= 'A') && (ch <= 'F'))
	{
		return ch - 'A' + 10;
	}
	else
	{
		return -1;
	}
}
/*******************************
函数功能：
	quoterprinter解码
参数：
	src -- 编码字符串
	srclen -- 解码部分的长度
	dst -- 解码后的字符串
	dstlen -- 解码字符串的长度
返回值：
	成功返回解码后字符串的长度
	失败返回-1
*************************************/
int CCharsetConver::DecoderQuoterPrinter(const char *src, int srclen, char *dst, int dstlen)
{
	int index = 0;
	const char *tmp = src;

	while(*src != '\0')
	{
		if(src - tmp > srclen)
		{
			break;
		}
		if(index >= dstlen)
		{
			return -1;
		}
		if(*src == '=')
		{
			if((src - tmp + 2) <= (INT)strlen(tmp))
			{
				char ch = QuotedPrintableFlag(*(src + 1));
				char cl = QuotedPrintableFlag(*(src + 2));
				if((ch != -1) || (cl != -1))
				{
					dst[index++] = (ch << 4) | cl;
				}
				src += 3;
			}
			else
			{
				break;
			}
		}
		else
		{
			dst[index++] = *src++;
		}
	}
	dst[index] = '\0';
	return index;
}

int CCharsetConver::Decoder7Bit(const char *src, int srclen, char *dst, int dstlen)
	//int            Decode7bit(const char *pSrc, int srcLen, char *pDst, int dstLen);
{
	int nSrc;        // 源字符串的计数值
    int nDst;        // 目标解码串的计数值
    int nByte;       // 当前正在处理的组内字节的序号，范围是0-6
	int nCount;			
	int nMaxCount;	 // 分组最大数
    unsigned char nLeft;    // 上一字节残余的数据
    
    // 计数值初始化
    nSrc = 0;
    nDst = 0;

    // 组内字节序号和残余数据初始化
    nByte = 0;
    nLeft = 0;

    nCount = 0;
	nMaxCount = srclen / 7 > (dstlen - 1) / 8 ? (dstlen - 1) / 8 : srclen / 7;

    // 将源数据每7个字节分为一组，解压缩成8个字节
    // 循环该处理过程，直至源数据被处理完
    // 如果分组不到7字节，也能正确处理
    while(nSrc < srclen)
    {
        // 将源字节右边部分与残余数据相加，去掉最高位，得到一个目标解码字节
        *dst = ((*src << nByte) | nLeft) & 0x7f;
        // 将该字节剩下的左边部分，作为残余数据保存起来
        nLeft = *src >> (7 - nByte);
    
        // 修改目标串的指针和计数值
        dst++;
        nDst++;
    
        // 修改字节计数值
        nByte++;
    
        // 到了一组的最后一个字节
        if(nByte == 7)
        {
            // 额外得到一个目标解码字节
            *dst = nLeft;
    
            // 修改目标串的指针和计数值
            dst++;
            nDst++;
    
            // 组内字节序号和残余数据初始化
            nByte = 0;
            nLeft = 0;
			nCount++;
			if(nCount > nMaxCount)
			{
				dst++;
				break;
			}
        }
    
        // 修改源串的指针和计数值
        src++;
        nSrc++;
    }
    
    *dst = 0;
    
    // 返回目标串长度
    return nDst;
}


int CCharsetConver::Decoder8Bit(const char *src, int srclen, char *dst, int dstlen)
{
	int nSrc;        // 源字符串的计数值
    int nDst;        // 目标解码串的计数值
    int nByte;       // 当前正在处理的组内字节的序号，范围是0-7
	int nCount;			
	int nMaxCount;	 // 分组最大数
    unsigned char nLeft;    // 上一字节残余的数据
    
    // 计数值初始化
    nSrc = 0;
    nDst = 0;

    // 组内字节序号和残余数据初始化
    nByte = 0;
    nLeft = 0;

    nCount = 0;
	nMaxCount = srclen / 8 > (dstlen - 1) / 9 ? (dstlen - 1) / 9 : srclen / 8;

    // 将源数据每8个字节分为一组，解压缩成9个字节
    // 循环该处理过程，直至源数据被处理完
    // 如果分组不到8字节，也能正确处理
    while(nSrc < srclen)
    {
        // 将源字节右边部分与残余数据相加，去掉最高位，得到一个目标解码字节
        *dst = ((*src << nByte) | nLeft) & 0x7f;
        // 将该字节剩下的左边部分，作为残余数据保存起来
        nLeft = *src >> (8 - nByte);
    
        // 修改目标串的指针和计数值
        dst++;
        nDst++;
    
        // 修改字节计数值
        nByte++;
    
        // 到了一组的最后一个字节
        if(nByte == 8)
        {
            // 额外得到一个目标解码字节
            *dst = nLeft;
    
            // 修改目标串的指针和计数值
            dst++;
            nDst++;
    
            // 组内字节序号和残余数据初始化
            nByte = 0;
            nLeft = 0;
			nCount++;
			if(nCount > nMaxCount)
			{
				dst++;
				break;
			}
        }
    
        // 修改源串的指针和计数值
        src++;
        nSrc++;
    }
    
    *dst = 0;
    
    // 返回目标串长度
    return nDst;
}