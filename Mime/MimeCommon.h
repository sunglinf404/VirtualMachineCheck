#pragma once

#include "Base64.h"
#include "MimeBuffer.h"
#include "CharsetConver.h"

const string MimeMailFrom = "MAIL FROM";
const string MimeRcptTo = "RCPT TO";

const string MimeFrom = "From";										//收件人标志
const string MimeTo = "To";											//发件人标志
const string MimeCc	=  "Cc";										//抄送标志
const string MimeBcc = "Bcc";										//密送标志
const string MimeSubject = "Subject";								//主题标志
const string MimeDate = "Date";										//日期
const string MimeContentType =	"Content-Type";						//媒体类型标志
const string MimeContentEncoder = "Content-Transfer-Encoding";		//编码格式标志
const string MimeBoundaryFlag = "boundary";							//边界界定线标志
const string MimeCharSetFlag = "charset";							//字符集标志
const string MimeContentDispostion = "Content-Disposition";			//内容处理方式标志
const string MimeFileName = "filename=";							//附件名标志
const string MimeBeginFlag = ":";									//字段值开始标志
const string MimeEndFlag = "\r\n";									//字段值结束标志
const string MimeEndFlagEx = "\n";									//字段值结束标志
const string MimeEndFlagOfHeader = "\r\n\r\n";						//头部与主体分割标志

const string MimeAttachmentFlag =	"attachment";					//附件标志
const string MimeBase64Encoder = "base64";							//base64编码标志
const string MimeQuoterPrinterEncoder = "quoted-printable";			//quoter_printed编码标志
const string Mime7BitEncoder = "7bit";								//7bit编码标志
const string Mime8BitEncoder = "8bit";								//8bit编码标志	

const string MimeContentFlag = "text";								//正文标志
const string MimeMultiPartMixedFlag = "multipart/mixed";			//复合媒体类型中的mixed子类型标志
const string MimeMultiPartAlternativeFlag = "multipart/alternative";//复合媒体类型中的alternative子类型标志
const string MimeMultiPartFlag = "multipart";						//复合媒体类型标志

const string MimeEncoderBeginFlag = "=?";							//编码开始标志
const string MimeEncoderFlag = "?";									//分割标志
const string MimeEncoderEndFlag = "?=";								//编码结束标志

const string MimeChunkedEndFlag = "\r\n0\r\n\r\n";                  //chunked结束标记

class CMimeCommon
{
private:
	static char* memchr_ex(const char *src, char c, size_t len);
	static char* memchr_rex(const char *src, char c, size_t len);
public:
	CMimeCommon(void);
	~CMimeCommon(void);
public:
	static char* memfind(const char *src, size_t srclen, const char *dst, size_t dstlen);
	static char* memrfind(const char *src, size_t srclen, const char *dst, size_t dstlen);

	static string lowerToUpper(const string &src);
	static string upperToLower(const string &src);

	static string mimeDecoder(const string &src, CMimeBuffer* pMimebuffer);

	static string GetSessionID(const char* proto, const uint32 sip, const uint16 sport);
};

