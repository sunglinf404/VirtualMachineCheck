#include "stdafx.h"
#include "MimeBuffer.h"


CMimeBuffer::CMimeBuffer(const uint32 size, const uint32 widesize)
{
	m_DecodeBufferSize = size;
	m_DecodeWideBufferSize = widesize;

	m_BufferSize = MAX_TEMPORARY_MEMORY_LEN;
	m_Buffer = (char *)malloc(m_BufferSize);
	if(m_Buffer == NULL)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"CMimeData 初始插件临时内存(len=%d)失败,错误信息:%s",
			m_BufferSize,CFuncs::SvcFormatMessage().c_str());
		throw CException("初始插件临时内存失败",0);
	}

	m_DecodeBuffer = (char *)malloc(m_DecodeBufferSize);
	if(m_DecodeBuffer == NULL)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"CMimeData 初始解码内存(len=%d)失败,错误信息:%s",
			m_DecodeBufferSize,CFuncs::SvcFormatMessage().c_str());
		throw CException("初始解码内存失败",0);
	}

	m_DecodeWideBuffer = (wchar_t *)malloc(m_DecodeWideBufferSize);
	if(m_DecodeWideBuffer == NULL)
	{
		CFuncs::WriteLogInfo(SLT_ERROR,"CMimeData 初始解码宽内存(len=%d)失败,错误信息:%s",
			m_DecodeWideBufferSize,CFuncs::SvcFormatMessage().c_str());
		throw CException("初始解码宽内字符存失败",0);
	}
}

CMimeBuffer::~CMimeBuffer(void)
{
	m_BufferSize = 0;
	if(m_Buffer != NULL)
	{
		free(m_Buffer);
		m_Buffer = NULL;
	}

	m_DecodeBufferSize = 0;
	if(m_DecodeBuffer != NULL)
	{
		free(m_DecodeBuffer);
		m_DecodeBuffer = NULL;
	}

	m_DecodeWideBufferSize = 0;
	if(m_DecodeWideBuffer != NULL)
	{
		free(m_DecodeWideBuffer);
		m_DecodeWideBuffer = NULL;
	}
}

char*  CMimeBuffer::getBuffer(void)
{
	return m_Buffer;
}

uint32 CMimeBuffer::getBufferSize(void)
{
	return m_BufferSize;
}

void   CMimeBuffer::ClearBuffer(void)
{
	if(NULL != m_Buffer)
	{
		memset(m_Buffer,0,m_BufferSize);
	}
}

char* CMimeBuffer::getDecodeBuffer(void)
{
	return m_DecodeBuffer;
}

uint32 CMimeBuffer::getDecodeBufferSize(void)
{
	return m_DecodeBufferSize;
}

void CMimeBuffer::ClearDecodeBuffer(void)
{
	if(NULL != m_DecodeBuffer)
	{
		memset(m_DecodeBuffer,0,m_DecodeBufferSize);
	}
}

wchar_t* CMimeBuffer::getDecodeWideBuffer(void)
{
	return m_DecodeWideBuffer;
}

uint32 CMimeBuffer::getDecodeWideBufferSize(void)
{
	return m_DecodeWideBufferSize;
}

void CMimeBuffer::ClearDecodeWideBuffer(void)
{
	if(NULL != m_DecodeWideBuffer)
	{
		memset(m_DecodeWideBuffer,0,m_DecodeWideBufferSize);
	}
}