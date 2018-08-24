#include "stdafx.h"
#include "MimeData.h"

CMimeData::CMimeData(CMimeBuffer* pMimebuffer):header(pMimebuffer),body(pMimebuffer)
{
	m_MimeBuffer = pMimebuffer;
}

CMimeData::~CMimeData(void)
{

}

void CMimeData::initMimeData(const char *src, size_t len, const char* savePath)
{
	char *tmp = CMimeCommon::memfind(src, len, MimeEndFlagOfHeader.c_str(), MimeEndFlagOfHeader.size());
	if (tmp != NULL)
	{
		if(!header.initMimeDataHeader(src, tmp - src))
		{
			return;
		}
		body.HandleMimeDataBody(tmp + MimeEndFlagOfHeader.size(),len - (tmp + MimeEndFlagOfHeader.size() - src), header.boundary, savePath);
	}
}

void CMimeData::initMimeData(const char *src, size_t len)
{
	char *tmp = CMimeCommon::memfind(src, len, MimeEndFlagOfHeader.c_str(), MimeEndFlagOfHeader.size());
	if (tmp != NULL)
	{
		if(!header.initMimeDataHeader(src, tmp - src))
		{
			return;
		}
		body.HandleMimeDataBody(tmp + MimeEndFlagOfHeader.size(),len - (tmp + MimeEndFlagOfHeader.size() - src), header.boundary);
	}
}


void CMimeData::clearMimeData()
{
	header.clearMimeDataHeader();
	body.clearMimeDataBody();
}

void CMimeData::InitAttachmentPath(const string &filePath)
{
	body.InitAtthPath(filePath);
}

void CMimeData::InitAtthmentTag(const std::string &tag)
{
	body.InitAtthTag(tag);
}

void CMimeData::InitWriteAtthFilePointer(WriteFileFuncPointer fpWritePointer)
{
	body.InitWriteFilePointer(fpWritePointer);
}

void CMimeData::InitCurrentTime(size_t currTime)
{
	body.InitCurrentTime(currTime);
}