#pragma once
#include "dlsqlite3.h"
#include "../Common/Define.h"

#define DBSQLITE_ERROR 1000

class CDbSqlite3Exception
{
private:
	int m_ErrCode;
	char* m_ErrMsg;

public:
	CDbSqlite3Exception(const int errCode, char* errMsg, bool bDelete = true);
	CDbSqlite3Exception(const CDbSqlite3Exception&  e);
	virtual ~CDbSqlite3Exception(void);
public:
	const int errorCode(void) 
	{ 
		return m_ErrCode;
	}

	const char* errorMessage(void)
	{ 
		return m_ErrMsg;
	}

	static const char* errorCodeAsString(int errCode);
};