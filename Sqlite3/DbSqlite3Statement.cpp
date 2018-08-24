#include "stdafx.h"
#include "DbSqlite3Statement.h"

CppSQLite3Statement::CppSQLite3Statement()
{
	mpDB = 0;
	mpVM = 0;
}


CppSQLite3Statement::CppSQLite3Statement(const CppSQLite3Statement& rStatement)
{
	mpDB = rStatement.mpDB;
	mpVM = rStatement.mpVM;
	// Only one object can own VM
	const_cast<CppSQLite3Statement&>(rStatement).mpVM = 0;
}


CppSQLite3Statement::CppSQLite3Statement(sqlite3* pDB, sqlite3_stmt* pVM)
{
	mpDB = pDB;
	mpVM = pVM;
}


CppSQLite3Statement::~CppSQLite3Statement()
{
	try
	{
		finalize();
	}
	catch (...)
	{
	}
}


CppSQLite3Statement& CppSQLite3Statement::operator=(const CppSQLite3Statement& rStatement)
{
	mpDB = rStatement.mpDB;
	mpVM = rStatement.mpVM;
	// Only one object can own VM
	const_cast<CppSQLite3Statement&>(rStatement).mpVM = 0;
	return *this;
}


int CppSQLite3Statement::execDML()
{
	checkDB();
	checkVM();

	const char* szError = 0;

	int nRet = sqlite3_step(mpVM);

	if (nRet == SQLITE_DONE)
	{
		int nRowsChanged = sqlite3_changes(mpDB);

		nRet = sqlite3_reset(mpVM);

		if (nRet != SQLITE_OK)
		{
			szError = sqlite3_errmsg(mpDB);
			throw CDbSqlite3Exception(nRet, (char*)szError, false);
		}

		return nRowsChanged;
	}
	else
	{
		nRet = sqlite3_reset(mpVM);
		szError = sqlite3_errmsg(mpDB);
		throw CDbSqlite3Exception(nRet, (char*)szError, false);
	}
}


CppSQLite3Query CppSQLite3Statement::execQuery()
{
	checkDB();
	checkVM();

	int nRet = sqlite3_step(mpVM);

	if (nRet == SQLITE_DONE)
	{
		// no rows
		return CppSQLite3Query(mpDB, mpVM, true/*eof*/, false);
	}
	else if (nRet == SQLITE_ROW)
	{
		// at least 1 row
		return CppSQLite3Query(mpDB, mpVM, false/*eof*/, false);
	}
	else
	{
		nRet = sqlite3_reset(mpVM);
		const char* szError = sqlite3_errmsg(mpDB);
		throw CDbSqlite3Exception(nRet, (char*)szError, false);
	}
}


void CppSQLite3Statement::bind(int nParam, const char* szValue)
{
	checkVM();
	int nRes = sqlite3_bind_text(mpVM, nParam, szValue, -1, SQLITE_TRANSIENT);

	if (nRes != SQLITE_OK)
	{
		throw CDbSqlite3Exception(nRes,
			"Error binding string param",
			false);
	}
}


void CppSQLite3Statement::bind(int nParam, const int nValue)
{
	checkVM();
	int nRes = sqlite3_bind_int(mpVM, nParam, nValue);

	if (nRes != SQLITE_OK)
	{
		throw CDbSqlite3Exception(nRes,
			"Error binding int param",
			false);
	}
}


void CppSQLite3Statement::bind(int nParam, const double dValue)
{
	checkVM();
	int nRes = sqlite3_bind_double(mpVM, nParam, dValue);

	if (nRes != SQLITE_OK)
	{
		throw CDbSqlite3Exception(nRes,
			"Error binding double param",
			false);
	}
}


void CppSQLite3Statement::bind(int nParam, const unsigned char* blobValue, int nLen)
{
	checkVM();
	int nRes = sqlite3_bind_blob(mpVM, nParam,
		(const void*)blobValue, nLen, SQLITE_TRANSIENT);

	if (nRes != SQLITE_OK)
	{
		throw CDbSqlite3Exception(nRes,
			"Error binding blob param",
			false);
	}
}


void CppSQLite3Statement::bindNull(int nParam)
{
	checkVM();
	int nRes = sqlite3_bind_null(mpVM, nParam);

	if (nRes != SQLITE_OK)
	{
		throw CDbSqlite3Exception(nRes,
			"Error binding NULL param",
			false);
	}
}


void CppSQLite3Statement::reset()
{
	if (mpVM)
	{
		int nRet = sqlite3_reset(mpVM);

		if (nRet != SQLITE_OK)
		{
			const char* szError = sqlite3_errmsg(mpDB);
			throw CDbSqlite3Exception(nRet, (char*)szError, false);
		}
	}
}


void CppSQLite3Statement::finalize()
{
	if (mpVM)
	{
		int nRet = sqlite3_finalize(mpVM);
		mpVM = 0;

		if (nRet != SQLITE_OK)
		{
			const char* szError = sqlite3_errmsg(mpDB);
			throw CDbSqlite3Exception(nRet, (char*)szError, false);
		}
	}
}


void CppSQLite3Statement::checkDB()
{
	if (mpDB == 0)
	{
		throw CDbSqlite3Exception(DBSQLITE_ERROR,
			"Database not open",
			false);
	}
}


void CppSQLite3Statement::checkVM()
{
	if (mpVM == 0)
	{
		throw CDbSqlite3Exception(DBSQLITE_ERROR,
			"Null Virtual Machine pointer",
			false);
	}
}