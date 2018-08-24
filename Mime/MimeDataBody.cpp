#include "stdafx.h"
#include "MimeDataBody.h"

#define ATTACH_MAX_COUNT    (2000)           //附件的最大计数
#define ATTACH_DIRECTORY	("Attachment")

CMimeDataBody::CMimeDataBody(CMimeBuffer* pMimebuffer)
{
	m_MimeBuffer = pMimebuffer;
	clearMimeDataBody();
}

CMimeDataBody::~CMimeDataBody(void)
{

}

void CMimeDataBody::HandleMimeDataBody(const char *content, size_t len, const CMimeBoundary &boundary, const char* savePath)
{

	string tmp = boundary.getContentType();
	if(tmp.find(MimeMultiPartFlag) != string::npos)
	{
		if(boundary.getBoundary().size() == 0)
		{
			return;
		}

		multipartAlternative(content, len, boundary.getBoundary(), savePath);
	}
	//if(tmp.find(MultiPartMixedFlag) != string::npos)
	//{
	//	multipartMixed(content, len, boundary.getBoundary());
	//}
	//else if(tmp.find(MultiPartAlternativeFlag) != string::npos)
	//{
	//	multipartAlternative(content, len, boundary.getBoundary());
	//}
	else
	{
		discreptionTypeHandle(content, len, boundary, savePath);
	}
	
}

void CMimeDataBody::HandleMimeDataBody(const char *content, size_t len, const CMimeBoundary &boundary)
{

	string tmp = boundary.getContentType();
	if(tmp.find(MimeMultiPartFlag) != string::npos)
	{
		if(boundary.getBoundary().size() == 0)
		{
			return;
		}

		multipartAlternative(content, len, boundary.getBoundary());
	}
	//if(tmp.find(MultiPartMixedFlag) != string::npos)
	//{
	//	multipartMixed(content, len, boundary.getBoundary());
	//}
	//else if(tmp.find(MultiPartAlternativeFlag) != string::npos)
	//{
	//	multipartAlternative(content, len, boundary.getBoundary());
	//}
	else
	{
		discreptionTypeHandle(content, len, boundary);
	}
	
}

void CMimeDataBody::clearMimeDataBody()
{
	dataContent.clear();
	atthList.clear();
	atthPath.clear();
	atthTag.clear();
	time = 0;
	fpWriteFilePointer = NULL;
}

void CMimeDataBody::InitAtthPath(const string &filePath)
{
	atthPath = filePath;
}

void CMimeDataBody::InitAtthTag(const string &tag)
{
	atthTag = tag;
}

void CMimeDataBody::InitWriteFilePointer(WriteFileFuncPointer fpWritePointer)
{
	fpWriteFilePointer = fpWritePointer;
}

void CMimeDataBody::InitCurrentTime(size_t currTime)
{
	time = currTime;
}

void CMimeDataBody::discreptionTypeHandle(const char *content, size_t len, const CMimeBoundary &boundary, const char* savePath)
{
	if(len <= 0)
	{
		return;
	}

	if(len >= MAX_DECODE_MEMORY_LEN)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"文件大小超过%dMB，丢弃该文件.",MAX_DECODE_MEMORY_LEN);
		return;
	}

	if(boundary.getContentType().find(MimeContentFlag) == string::npos)		//是否正文文本
	{
		if(boundary.getContentDisposition().size() == 0)				//是否是附件
		{
			return;				//只处理正文文件和附件，其他类型咱不处理
		}
	}

	string tmp = boundary.getContentEncoder();
	memset(m_MimeBuffer->getDecodeBuffer(), 0, len + 1);
	memcpy(m_MimeBuffer->getDecodeBuffer(), content, len);

	//开始解码
	int index = 0, length = 0;
	if((index = static_cast<int>(tmp.find(MimeBase64Encoder))) != string::npos)
	{
		length = CBase64::Decode((uint8 *)content, static_cast<int>(len), 
			(uint8 *)(m_MimeBuffer->getDecodeBuffer()),m_MimeBuffer->getDecodeBufferSize());
		if (length == -1)
		{
			string errorInfo = "Content-type: " + boundary.getContentType();
			errorInfo += "中内容进行base64解码错误。";
			CFuncs::WriteLogInfo(SLT_ERROR, errorInfo);
			return;
		}
	}
	else if((index = static_cast<int>(tmp.find(MimeQuoterPrinterEncoder))) != string::npos)
	{
		length = CCharsetConver::DecoderQuoterPrinter(content, static_cast<int>(len),
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
		if(length == -1)
		{
			string errorInfo = "Content-type: " + boundary.getContentType();
			errorInfo += "中内容进行QuoterPrinter解码错误。";
			CFuncs::WriteLogInfo(SLT_ERROR, errorInfo);
			return;
		}
	}
	else if((index = static_cast<int>(tmp.find(Mime8BitEncoder))) != string::npos)
	{
		length = CCharsetConver::DecoderQuoterPrinter(content, static_cast<int>(len),
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
		if(length == -1)
		{
			string errorInfo = "Content-type: " + boundary.getContentType();
			errorInfo += "中内容进行QuoterPrinter解码错误。";
			CFuncs::WriteLogInfo(SLT_ERROR, errorInfo);
			return;
		}
	}
	//开始编码转换
	if(CMimeCommon::upperToLower(boundary.getCharSet()).find("utf-8") != string::npos)
	{
		length = CCharsetConver::UTF8ToUnicode(m_MimeBuffer->getDecodeBuffer(),length,
			m_MimeBuffer->getDecodeWideBuffer(),m_MimeBuffer->getDecodeWideBufferSize());
		length = CCharsetConver::UnicodeToANSI(m_MimeBuffer->getDecodeWideBuffer(),length,
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
	}
	else if(CMimeCommon::upperToLower(boundary.getCharSet()).find("iso-2022-jp") != string::npos)
	{
		length = CCharsetConver::ISO2022JPToUnicode(m_MimeBuffer->getDecodeBuffer(),length,
			m_MimeBuffer->getDecodeWideBuffer(),m_MimeBuffer->getDecodeWideBufferSize());
		length = CCharsetConver::UnicodeToANSI(m_MimeBuffer->getDecodeWideBuffer(),length,
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
	}
	else if(CMimeCommon::upperToLower(boundary.getCharSet()).find("big5") != string::npos)
	{
		length = CCharsetConver::BIG5ToUnicode(m_MimeBuffer->getDecodeBuffer(),length,
			m_MimeBuffer->getDecodeWideBuffer(),m_MimeBuffer->getDecodeWideBufferSize());
		length = CCharsetConver::UnicodeToGB2312(m_MimeBuffer->getDecodeWideBuffer(),length,
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
	}

	//保存结果
	if(boundary.getContentDisposition().find(MimeAttachmentFlag) != string::npos)
	{
		if(boundary.getFileName().empty())		//不处理附件名为空的情况
		{
			return;
		}
		if(fpWriteFilePointer == NULL)
		{
			writeAtthFile(boundary.getFileName(), m_MimeBuffer->getDecodeBuffer(), length, savePath);
		}
		else
		{
			string filePath = "";
			fpWriteFilePointer(boundary.getFileName(), m_MimeBuffer->getDecodeBuffer(), length, filePath, time);
			AttachData attachData;
			attachData.fileSize = length;
			attachData.fileName = boundary.getFileName();
			attachData.filePath = filePath;
			atthList.push_back(attachData);
		}
	}
	else
	{
		if(boundary.getContentType().find(MimeContentFlag) != string::npos)
		{
			dataContent = m_MimeBuffer->getDecodeBuffer();
		}
	}
}

void CMimeDataBody::discreptionTypeHandle(const char *content, size_t len, const CMimeBoundary &boundary)
{
	if(len <= 0)
	{
		return;
	}

	if(len >= MAX_DECODE_MEMORY_LEN)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"文件大小超过%dMB，丢弃该文件.",MAX_DECODE_MEMORY_LEN);
		return;
	}

	if(boundary.getContentType().find(MimeContentFlag) == string::npos)		//是否正文文本
	{
		if(boundary.getContentDisposition().size() == 0)				//是否是附件
		{
			return;				//只处理正文文件和附件，其他类型咱不处理
		}
	}

	string tmp = boundary.getContentEncoder();
	memset(m_MimeBuffer->getDecodeBuffer(), 0, len + 1);
	memcpy(m_MimeBuffer->getDecodeBuffer(), content, len);

	//开始解码
	int index = 0, length = 0;
	if((index = static_cast<int>(tmp.find(MimeBase64Encoder))) != string::npos)
	{
		length = CBase64::Decode((uint8 *)content, static_cast<int>(len), 
			(uint8 *)(m_MimeBuffer->getDecodeBuffer()),m_MimeBuffer->getDecodeBufferSize());
		if (length == -1)
		{
			string errorInfo = "Content-type: " + boundary.getContentType();
			errorInfo += "中内容进行base64解码错误。";
			CFuncs::WriteLogInfo(SLT_ERROR, errorInfo);
			return;
		}
	}
	else if((index = static_cast<int>(tmp.find(MimeQuoterPrinterEncoder))) != string::npos)
	{
		length = CCharsetConver::DecoderQuoterPrinter(content, static_cast<int>(len),
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
		if(length == -1)
		{
			string errorInfo = "Content-type: " + boundary.getContentType();
			errorInfo += "中内容进行QuoterPrinter解码错误。";
			CFuncs::WriteLogInfo(SLT_ERROR, errorInfo);
			return;
		}
	}
	//开始编码转换
	if(CMimeCommon::upperToLower(boundary.getCharSet()).find("utf-8") != string::npos)
	{
		length = CCharsetConver::UTF8ToUnicode(m_MimeBuffer->getDecodeBuffer(),length,
			m_MimeBuffer->getDecodeWideBuffer(),m_MimeBuffer->getDecodeWideBufferSize());
		length = CCharsetConver::UnicodeToANSI(m_MimeBuffer->getDecodeWideBuffer(),length,
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
	}
	else if(CMimeCommon::upperToLower(boundary.getCharSet()).find("iso-2022-jp") != string::npos)
	{
		length = CCharsetConver::ISO2022JPToUnicode(m_MimeBuffer->getDecodeBuffer(),length,
			m_MimeBuffer->getDecodeWideBuffer(),m_MimeBuffer->getDecodeWideBufferSize());
		length = CCharsetConver::UnicodeToANSI(m_MimeBuffer->getDecodeWideBuffer(),length,
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
	}
	else if(CMimeCommon::upperToLower(boundary.getCharSet()).find("big5") != string::npos)
	{
		length = CCharsetConver::BIG5ToUnicode(m_MimeBuffer->getDecodeBuffer(),length,
			m_MimeBuffer->getDecodeWideBuffer(),m_MimeBuffer->getDecodeWideBufferSize());
		length = CCharsetConver::UnicodeToGB2312(m_MimeBuffer->getDecodeWideBuffer(),length,
			m_MimeBuffer->getDecodeBuffer(),m_MimeBuffer->getDecodeBufferSize());
	}

	//保存结果
	if(boundary.getContentDisposition().find(MimeAttachmentFlag) != string::npos)
	{
		if(boundary.getFileName().empty())		//不处理附件名为空的情况
		{
			return;
		}
		if(fpWriteFilePointer == NULL)
		{
			writeAtthFile(boundary.getFileName(), m_MimeBuffer->getDecodeBuffer(), length);
		}
		else
		{
			string filePath = "";
			fpWriteFilePointer(boundary.getFileName(), m_MimeBuffer->getDecodeBuffer(), length, filePath, time);
			AttachData attachData;
			attachData.fileSize = length;
			attachData.fileName = boundary.getFileName();
			attachData.filePath = filePath;
			atthList.push_back(attachData);
		}
	}
	else
	{
		if(boundary.getContentType().find(MimeContentFlag) != string::npos)
		{
			dataContent = m_MimeBuffer->getDecodeBuffer();
		}
	}
}
/*
void CMimeDataBody::boundaryHandler(Boundary &boundary)
{

	int index = 0;
	string content = boundary.getContent();
	string tmp = boundary.getContentEncoder();
	//char *buf = new char[content.size() + 1];
	//if(buf == NULL)
	//{
	//	WaFuncs::WriteLogInfo( "函数boundaryHandler中分配内存失败.");
	//	return;
	//}
	//memset(buf, 0, content.size() + 1);
	//memcpy(buf, content.c_str(), content.size());

	if(content.size() >= MAX_MEMORY_LEN)
	{
		string errorinfo = "文件大小超过10M，丢弃该文件.";
		if(boundary.getFileName().size() != 0)
		{
			errorinfo += "该文件名为：";
			errorinfo += boundary.getFileName();
		}
		WaFuncs::WriteLogInfo( errorinfo);
		return;
	}
	memset(decoderBuf, 0, content.size() + 1);
	memcpy(decoderBuf, content.c_str(), content.size());

	int length = 0;
	if((index = static_cast<int>(tmp.find(Base64Encoder))) != string::npos)
	{
		length = base64Decoder(content.c_str(), decoderBuf, MAX_MEMORY_LEN);
		if (length == -1)
		{
			string errorInfo = "Content-type: " + boundary.getContentType();
			errorInfo += "中内容进行base64解码错误。";
			WaFuncs::WriteLogInfo( errorInfo);
			return;
		}
	}
	else if((index = static_cast<int>(tmp.find(QuoterPrinterEncoder))) != string::npos)
	{
		length = quoterPrinterDecoder(content.c_str(), decoderBuf, MAX_MEMORY_LEN);
		if(length == -1)
		{
			string errorInfo = "Content-type: " + boundary.getContentType();
			errorInfo += "中内容进行quoter_printer解码错误.";
			WaFuncs::WriteLogInfo( errorInfo);
			return;
		}
	}
	if(upperToLower(boundary.getCharSet()).find("utf-8") != string::npos)
	{
		//wchar_t *tmpbuf = utf8ToUnicode(buf);
		//char *tmp = unicodeToAnsi(tmpbuf);
		//delete [] tmpbuf;
		//delete [] buf;
		////char *tmp = unicodeToAnsi(utf8ToUnicode(buf));
		////delete buf;
		//buf = tmp;
		Utf8ToUnicode(decoderBuf);
		UnicodeToAnsi(convertBufTmp);
		if(strlen(convertBuf) >= MAX_MEMORY_LEN)
		{
			return;
		}
		memset(decoderBuf, 0, strlen(convertBuf) + 1);
		memcpy(decoderBuf, convertBuf, strlen(convertBuf));
	}

	if(boundary.getContentDisposition().find(AttachmentFlag) != string::npos)
	{
		atthList.push_back(boundary.getFileName());
#ifdef WRITEATTHFILE
		writeAtthFile(boundary.getFileName(), decoderBuf, length);
#endif
	}
	else
	{
		dataContent = decoderBuf;
	}
	
	
	//delete [] buf;
}
*/

void CMimeDataBody::multipartAlternative(const char *str, size_t len, const string &boundary, const char* savePath)
{
	string newBoundary = "--" + boundary;
	char *pBegin = (char *)str;
	char *pEnd = NULL;
	char *pIndex = NULL;
	size_t offset = 0;
	
	offset = pBegin - str;
	while((pIndex = CMimeCommon::memfind(pBegin, len - offset, newBoundary.c_str(), newBoundary.size())) != NULL)
	{
		pIndex += newBoundary.size();
		offset = pIndex - str;
		pEnd = CMimeCommon::memfind(pIndex, len - offset, newBoundary.c_str(), newBoundary.size());
		if(pEnd != NULL)
		{
			//string boundaryContent = string(pIndex + newBoundary.size(), pEnd - pIndex - newBoundary.size());
			pIndex += MimeEndFlag.size();

			CMimeBoundary tmp(m_MimeBuffer);
			if(tmp.initBoundary(pIndex, static_cast<int>(pEnd - pIndex)))
			{
				HandleMimeDataBody(tmp.getContent(), tmp.getContentLength(), tmp, savePath);
			}
			pBegin = pEnd;
			offset = pBegin - str;
		}
		else
		{
			break;
		}
	}

}

void CMimeDataBody::multipartAlternative(const char *str, size_t len, const string &boundary)
{
	string newBoundary = "--" + boundary;
	char *pBegin = (char *)str;
	char *pEnd = NULL;
	char *pIndex = NULL;
	size_t offset = 0;
	
	offset = pBegin - str;
	while((pIndex = CMimeCommon::memfind(pBegin, len - offset, newBoundary.c_str(), newBoundary.size())) != NULL)
	{
		pIndex += newBoundary.size();
		offset = pIndex - str;
		pEnd = CMimeCommon::memfind(pIndex, len - offset, newBoundary.c_str(), newBoundary.size());
		if(pEnd != NULL)
		{
			//string boundaryContent = string(pIndex + newBoundary.size(), pEnd - pIndex - newBoundary.size());
			pIndex += MimeEndFlag.size();

			CMimeBoundary tmp(m_MimeBuffer);
			if(tmp.initBoundary(pIndex, static_cast<int>(pEnd - pIndex)))
			{
				HandleMimeDataBody(tmp.getContent(), tmp.getContentLength(), tmp);
			}
			pBegin = pEnd;
			offset = pBegin - str;
		}
		else
		{
			break;
		}
	}

}
void CMimeDataBody::multipartMixed(const char *str, int len, const string &boundary)
{
	/*
	string newBoundary = "--" + boundary;
	char *pBegin = (char *)str;
	char *pEnd = NULL;
	char *pIndex = NULL;
	
	while((pIndex = memfind(pBegin, len - (pBegin - str), newBoundary.c_str(), newBoundary.size())) != NULL)
	{
		pEnd = memfind(pIndex + newBoundary.size(), len - (pIndex + newBoundary.size() - str), newBoundary.c_str(), newBoundary.size());
		if(pEnd != NULL)
		{
			string boundaryContent = string(pIndex + newBoundary.size(), pEnd - pIndex - newBoundary.size());
			Boundary tmp;
			tmp.initBoundary(boundaryContent);
			if(tmp.getContentType().find(MultiPartAlternativeFlag) != string::npos)
			{
				multipartAlternative(tmp.getContent().c_str(), tmp.getContent().size(), tmp.getBoundary());
			}
			else
			{
				boundaryHandler(tmp);
			}
			pBegin = pEnd;
		}
		else
		{
			break;
		}
	}
	*/
	//int begin = 0, end = 0, index = 0;
	//while((index = static_cast<int>(str.find(newBoundary, begin))) != string::npos)
	//{
	//	end = static_cast<int>(str.find(newBoundary, index + newBoundary.size()));
	//	if(end != string::npos)
	//	{
	//		string boundaryContent = str.substr(index + newBoundary.size(), end - index - newBoundary.size());
	//		Boundary tmp;
	//		tmp.initBoundary(boundaryContent);

	//		if(tmp.getContentType().find(MultiPartAlternativeFlag) != string::npos)
	//		{
	//			multipartAlternative(tmp.getContent(), tmp.getBoundary());
	//		}
	//		else
	//			boundaryHandler(tmp);
	//	}
	//	begin = end;
	//}
}

void CMimeDataBody::writeAtthFile(const string &filename, const char *buf, int len)
{
	if(filename.size() == 0)
	{
		return;
	}
	FILE *ftStream = NULL;
	AttachData attachData;
	attachData.fileSize = len;
	attachData.fileName = filename;
	//attachData.filePath = gTemporaryPath;
	attachData.filePath = "";
	attachData.filePath.append("Attach_");
	attachData.filePath.append(CFuncs::GetGUID());
	attachData.filePath.append("_");
	attachData.filePath.append(filename);

	fopen_s(&ftStream, attachData.filePath.c_str(), "wb");
	if(ftStream == NULL)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"保存附件,打开附件文件(%s)失败,错误信息:%s)", 
			attachData.filePath.c_str(), CFuncs::SvcFormatMessage().c_str());
		return;
	}
	size_t ret = fwrite(buf, len, 1, ftStream);
	if(ret != 1)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"保存附件,写附件文件(%s)失败,错误信息:%s",
			attachData.filePath.c_str(), CFuncs::SvcFormatMessage().c_str());
		fclose(ftStream);
		return ;
	}
	fclose(ftStream);
	atthList.push_back(attachData);
}

void CMimeDataBody::writeAtthFile(const string &filename, const char *buf, int len, const char* savePath)
{
	if(filename.size() == 0 || NULL == savePath || 0 == len)
	{
		return;
	}
	FILE *ftStream = NULL;
	AttachData attachData;
	attachData.fileSize = len;
	attachData.fileName = filename;
	attachData.filePath = savePath;
	attachData.filePath.append("attach_");
	attachData.filePath.append(CFuncs::GetGUID());
	attachData.filePath.append("_");
	attachData.filePath.append(filename);

	fopen_s(&ftStream, attachData.filePath.c_str(), "wb");
	if(ftStream == NULL)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"保存附件,打开附件文件(%s)失败,错误信息:%s)", 
			attachData.filePath.c_str(), CFuncs::SvcFormatMessage().c_str());
		return;
	}
	size_t ret = fwrite(buf, len, 1, ftStream);
	if(ret != 1)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"保存附件,写附件文件(%s)失败,错误信息:%s",
			attachData.filePath.c_str(), CFuncs::SvcFormatMessage().c_str());
		fclose(ftStream);
		return ;
	}
	fclose(ftStream);
	atthList.push_back(attachData);
}

string CMimeDataBody::renameAtthFile(const std::string &filename)
{
	static UINT count = 0;
	time_t time = CFuncs::GetTimestamp();
	struct tm rawtime;
	char tmpFileName[256];
	string newFileName;

	char tmpBuf[32] = {0};
	sprintf_s(tmpBuf, "%u", count);
	count++;

	localtime_s(&rawtime, &time);
	memset(tmpFileName, 0, sizeof(tmpFileName));
	strftime(tmpFileName, sizeof(tmpFileName) - 1, "_%Y%m%d%H%M%S_", &rawtime);
	
	newFileName = atthPath;
	newFileName += atthTag;
	newFileName += tmpFileName;
	newFileName += tmpBuf;
	newFileName += "_";
	newFileName += filename;
	
	return newFileName;
}