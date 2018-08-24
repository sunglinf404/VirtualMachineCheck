#pragma once
#include "dlsqlite3.h"
#include "../Common/Define.h"
#include "DbSqlite3Exception.h"
#include "DbSqlite3Query.h"

class CppSQLite3Statement
{
public:

	CppSQLite3Statement();

	CppSQLite3Statement(const CppSQLite3Statement& rStatement);

	CppSQLite3Statement(sqlite3* pDB, sqlite3_stmt* pVM);

	virtual ~CppSQLite3Statement();

	CppSQLite3Statement& operator=(const CppSQLite3Statement& rStatement);

	int execDML();

	CppSQLite3Query execQuery();

	void bind(int nParam, const char* szValue);
	void bind(int nParam, const int nValue);
	void bind(int nParam, const double dwValue);
	void bind(int nParam, const unsigned char* blobValue, int nLen);
	void bindNull(int nParam);

	void reset();

	void finalize();

private:

	void checkDB();
	void checkVM();

	sqlite3* mpDB;
	sqlite3_stmt* mpVM;
};
