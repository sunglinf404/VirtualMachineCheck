#include "stdafx.h"
#include "DbSqlite3Binary.h"

CDbSQLite3Binary::CDbSQLite3Binary(void) :m_Buffer(0), m_BinaryLen(0), m_BufferLen(0), m_EncodedLen(0), m_bEncoded(false)
{
}

CDbSQLite3Binary::~CDbSQLite3Binary(void)
{
	Clear();
}

void CDbSQLite3Binary::SetBinary(const char* Buffer, int BufferLen)
{
	m_Buffer = AllocBuffer(BufferLen);
	memcpy(m_Buffer, Buffer, BufferLen);
}

void CDbSQLite3Binary::SetEncoded(const char* Buffer)
{
	Clear();
	m_EncodedLen = (int)strlen((const char*)Buffer);
	// Allow for NULL terminator
	m_EncodedLen = m_EncodedLen + 1; 
	m_Buffer = ( char*)malloc(m_BufferLen);
	if (NULL == m_Buffer)
	{
		throw CDbSqlite3Exception(DBSQLITE_ERROR, "SetEncoded ∑÷≈‰ƒ⁄¥Êbuffer ß∞‹!", false);
	}

	memcpy(m_Buffer, Buffer, m_BufferLen);
	m_bEncoded = true;
}

const char* CDbSQLite3Binary::GetEncoded(void)
{
	if (!m_bEncoded)
	{
		char* pTemp = (char*)malloc(m_BinaryLen);
		memcpy(pTemp, m_Buffer, m_BinaryLen);
		m_EncodedLen = sqlite3_encode_binary(pTemp, m_BinaryLen, m_Buffer);
		free(pTemp);
		m_bEncoded = true;
	}
	return m_Buffer;
}

const char* CDbSQLite3Binary::GetBinary(void)
{
	if (m_bEncoded)
	{
		// in/out buffers can be the same
		m_BinaryLen = sqlite3_decode_binary(m_Buffer, m_Buffer);

		if (m_BinaryLen == -1)
		{
			throw CDbSqlite3Exception(DBSQLITE_ERROR, "Cannot decode binary", false);
		}
		m_bEncoded = false;
	}
	return m_Buffer;
}

int CDbSQLite3Binary::getBinaryLength()
{
	GetBinary();
	return m_BinaryLen;
}

char* CDbSQLite3Binary::AllocBuffer(int length)
{
	Clear();
	// Allow extra space for encoded binary as per comments in
	// SQLite encode.c See bottom of this file for implementation
	// of SQLite functions use 3 instead of 2 just to be sure ;-)
	m_BinaryLen = length;
	m_BufferLen = 3 + (257 * length) / 254;

	m_Buffer = (char*)malloc(m_BufferLen);
	if (NULL == m_Buffer)
	{
		throw CDbSqlite3Exception(DBSQLITE_ERROR, "CDbSQLite3Binary::AllocBuffer ∑÷≈‰ƒ⁄¥Ê ß∞‹", false);
	}
	m_bEncoded = false;
	return m_Buffer;
}

void CDbSQLite3Binary::Clear(void)
{
	if (NULL != m_Buffer)
	{
		m_BinaryLen = 0;
		m_BufferLen = 0;
		free(m_Buffer);
		m_Buffer = NULL;
	}
}

int CDbSQLite3Binary::sqlite3_encode_binary(const char *in, int n, char *out) {
	int i, j, e, m;
	int cnt[256];
	if (n <= 0) {
		out[0] = 'x';
		out[1] = 0;
		return 1;
	}
	memset(cnt, 0, sizeof(cnt));
	for (i = n - 1; i >= 0; i--) { cnt[in[i]]++; }
	m = n;
	for (i = 1; i<256; i++) {
		int sum;
		if (i == '\'') continue;
		sum = cnt[i] + cnt[(i + 1) & 0xff] + cnt[(i + '\'') & 0xff];
		if (sum<m) {
			m = sum;
			e = i;
			if (m == 0) break;
		}
	}
	out[0] = e;
	j = 1;
	for (i = 0; i<n; i++) {
		int c = (in[i] - e) & 0xff;
		if (c == 0) {
			out[j++] = 1;
			out[j++] = 1;
		}
		else if (c == 1) {
			out[j++] = 1;
			out[j++] = 2;
		}
		else if (c == '\'') {
			out[j++] = 1;
			out[j++] = 3;
		}
		else {
			out[j++] = c;
		}
	}
	out[j] = 0;
	return j;
}

/*
** Decode the string "in" into binary data and write it into "out".
** This routine reverses the encoding created by sqlite3_encode_binary().
** The output will always be a few bytes less than the input.  The number
** of bytes of output is returned.  If the input is not a well-formed
** encoding, -1 is returned.
**
** The "in" and "out" parameters may point to the same buffer in order
** to decode a string in place.
*/
int CDbSQLite3Binary::sqlite3_decode_binary(const char *in,  char *out)
{
	int i, c, e;
	e = *(in++);
	i = 0;
	while ((c = *(in++)) != 0) {
		if (c == 1) {
			c = *(in++);
			if (c == 1) {
				c = 0;
			}
			else if (c == 2) {
				c = 1;
			}
			else if (c == 3) {
				c = '\'';
			}
			else {
				return -1;
			}
		}
		out[i++] = (c + e) & 0xff;
	}
	return i;
}