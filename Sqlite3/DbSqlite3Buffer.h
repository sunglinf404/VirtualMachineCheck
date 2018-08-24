#pragma once

#include "dlsqlite3.h"
#include "../Common/Define.h"

class CDbSqlite3Buffer
{
private:
	char* m_Buffer;
public:
	CDbSqlite3Buffer(void);
	~CDbSqlite3Buffer(void);
public:
	const char* Format(const char* szFormat, ...);

	void Clear(void);

	operator const char*(void) 
	{ 
		return m_Buffer;
	}
};
