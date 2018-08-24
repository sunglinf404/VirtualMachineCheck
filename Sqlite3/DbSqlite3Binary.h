#pragma once

#include "../Common/Define.h"
#include "DbSqlite3Exception.h"
#include "dlsqlite3.h"
static const bool DONT_DELETE_MSG = false;

//#define DBSQLITE_ERROR 1000

class CDbSQLite3Binary
{
private:
	char* m_Buffer;
	int  m_BinaryLen;
	int  m_BufferLen;
	int  m_EncodedLen;
	bool m_bEncoded;

	int sqlite3_encode_binary(const char* in, int n, char *out);
	int sqlite3_decode_binary(const char *in,  char* out);

public:
	CDbSQLite3Binary(void);
	~CDbSQLite3Binary(void);
public:
	void SetBinary(const char* buffer, int bufferLen);
	void SetEncoded(const char* buffer);
	const char* GetEncoded(void);
	const char* GetBinary(void);
	int getBinaryLength(void);
	char* AllocBuffer(int length);
	void Clear(void);


};

