#pragma once

#include "../Common/Funcs.h"
#include "../Common/Exception.h"

#define MAX_DECODE_MEMORY_LEN       (65 * 1024 * 1024)
#define MAX_TEMPORARY_MEMORY_LEN    (10 * 1024 * 1024)

class CMimeBuffer
{
private:
	char*       m_Buffer;
	uint32      m_BufferSize;

	char*       m_DecodeBuffer;
	uint32      m_DecodeBufferSize;

	wchar_t*    m_DecodeWideBuffer;
	uint32      m_DecodeWideBufferSize;
public:
	CMimeBuffer(const uint32 size, const uint32 widesize);
	~CMimeBuffer(void);
public:
	char*  getBuffer(void);
	uint32 getBufferSize(void);
	void   ClearBuffer(void);

	char*  getDecodeBuffer(void);
	uint32 getDecodeBufferSize(void);
	void   ClearDecodeBuffer(void);

	wchar_t* getDecodeWideBuffer(void);
	uint32   getDecodeWideBufferSize(void);
	void     ClearDecodeWideBuffer(void);

};
