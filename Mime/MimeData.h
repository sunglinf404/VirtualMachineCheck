#pragma once

#include "MimeDataHeader.h"
#include "MimeDataBody.h"
#include "../Common/Funcs.h"
#include "../Common/Exception.h"

class CMimeData
{
private:
	CMimeBuffer* m_MimeBuffer;  //±àÂë×ª»»ÄÚ´æ
public:
	CMimeData(CMimeBuffer* pMimebuffer);
	~CMimeData(void);
public:
	CMimeDataHeader header;
	CMimeDataBody   body;

	void initMimeData(const char *src, size_t len);
	void initMimeData(const char *src, size_t len, const char* savePath);
	void clearMimeData();
	void InitAttachmentPath(const string &filePath);
	void InitAtthmentTag(const string &tag);
	void InitWriteAtthFilePointer(WriteFileFuncPointer fpWritePointer);
	void InitCurrentTime(size_t currTime);

};
