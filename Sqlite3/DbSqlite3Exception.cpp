#include "stdafx.h"
#include "DbSqlite3Exception.h"

CDbSqlite3Exception::CDbSqlite3Exception(const int errCode, char* errMsg,bool bDelete) : m_ErrCode(errCode)
{
	m_ErrMsg = sqlite3_mprintf("%s[%d]: %s", errorCodeAsString(errCode), errCode, errMsg ? errMsg : NULL);
	if (bDelete && (NULL != errMsg))
	{
		sqlite3_free(errMsg);
	}
}

CDbSqlite3Exception::CDbSqlite3Exception(const CDbSqlite3Exception&  e) : m_ErrCode(e.m_ErrCode)
{
	m_ErrMsg = NULL;
	if (e.m_ErrMsg)
	{
		m_ErrMsg = sqlite3_mprintf("%s", e.m_ErrMsg);
	}
}

CDbSqlite3Exception::~CDbSqlite3Exception()
{
	if (m_ErrMsg)
	{
		sqlite3_free(m_ErrMsg);
		m_ErrMsg = NULL;
	}
}

const char* CDbSqlite3Exception::errorCodeAsString(int errCode)
{
	switch (errCode)
	{
	case SQLITE_OK:
		return "SQLITE_OK";
	case SQLITE_ERROR:
		return "SQLITE_ERROR";
	case SQLITE_INTERNAL:
		return "SQLITE_INTERNAL";
	case SQLITE_PERM:
		return "SQLITE_PERM";
	case SQLITE_ABORT:
		return "SQLITE_ABORT";
	case SQLITE_BUSY:
		return "SQLITE_BUSY";
	case SQLITE_LOCKED:
		return "SQLITE_LOCKED";
	case SQLITE_NOMEM:
		return "SQLITE_NOMEM";
	case SQLITE_READONLY:
		return "SQLITE_READONLY";
	case SQLITE_INTERRUPT:
		return "SQLITE_INTERRUPT";
	case SQLITE_IOERR:
		return "SQLITE_IOERR";
	case SQLITE_CORRUPT:
		return "SQLITE_CORRUPT";
	case SQLITE_NOTFOUND:
		return "SQLITE_NOTFOUND";
	case SQLITE_FULL:
		return "SQLITE_FULL";
	case SQLITE_CANTOPEN:
		return "SQLITE_CANTOPEN";
	case SQLITE_PROTOCOL:
		return "SQLITE_PROTOCOL";
	case SQLITE_EMPTY:
		return "SQLITE_EMPTY";
	case SQLITE_SCHEMA:
		return "SQLITE_SCHEMA";
	case SQLITE_TOOBIG:
		return "SQLITE_TOOBIG";
	case SQLITE_CONSTRAINT:
		return "SQLITE_CONSTRAINT";
	case SQLITE_MISMATCH:
		return "SQLITE_MISMATCH";
	case SQLITE_MISUSE:
		return "SQLITE_MISUSE";
	case SQLITE_NOLFS: return "SQLITE_NOLFS";
	case SQLITE_AUTH:
		return "SQLITE_AUTH";
	case SQLITE_FORMAT:
		return "SQLITE_FORMAT";
	case SQLITE_RANGE: return "SQLITE_RANGE";
	case SQLITE_ROW:
		return "SQLITE_ROW";
	case SQLITE_DONE:
		return "SQLITE_DONE";
	case DBSQLITE_ERROR:
		return "CPPSQLITE_ERROR";
	default:
		return "UNKNOWN_ERROR";
	}
}


