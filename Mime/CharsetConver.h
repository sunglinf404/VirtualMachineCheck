#pragma once

#include "../Common/Funcs.h"

class CCharsetConver
{
private:
	static int QuotedPrintableFlag(char ch);
public:
	CCharsetConver(void);
	~CCharsetConver(void);
public:
	static int ANSIToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen);

	static int UnicodeToANSI(const wchar_t *src, int srclen, char *dst, int dstlen);

	static int UnicodeToGB2312(const wchar_t *src, int srclen, char *dst, int dstlen);

	static int UTF8ToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen);

	static int UTF8ToGB2312(const char *src, int srclen, wchar_t *wdst, int wdstlen,char *dst, int dstlen);

	static int ISO2022JPToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen);

	static int BIG5ToUnicode(const char *src, int srclen, wchar_t *dst, int dstlen);

	static int BIG5ToGB2312(char *src, int srclen, wchar_t *wdst, int wdstlen, char* dst, int dstlen);

	static int BIG5TranslateGB2312(char *src, int srclen,char* dst, int dstlen);

	static int Decoder7Bit(const char *src, int srclen, char *dst, int dstlen);

	static int DecoderQuoterPrinter(const char *src, int srclen, char *dst, int dstlen);

	static int Decoder8Bit(const char *src, int srclen, char *dst, int dstlen);

};

