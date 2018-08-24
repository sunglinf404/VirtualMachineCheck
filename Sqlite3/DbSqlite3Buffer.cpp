#include "stdafx.h"
#include "DbSqlite3Buffer.h"


CDbSqlite3Buffer::CDbSqlite3Buffer()
{
	m_Buffer = NULL;
}

CDbSqlite3Buffer::~CDbSqlite3Buffer()
{
	Clear();
}

void CDbSqlite3Buffer::Clear(void)
{
	if (m_Buffer)
	{
		sqlite3_free(m_Buffer);
		m_Buffer = NULL;
	}
}


const char* CDbSqlite3Buffer::Format(const char* szFormat, ...)
{
	Clear();
	va_list vaList;
	va_start(vaList, szFormat);
	m_Buffer = sqlite3_vmprintf(szFormat, vaList);
	va_end(vaList);
	return m_Buffer;
}