////////////////////////////////////////////////////////////////////////////////
// CppSQLite3 - A C++ wrapper around the SQLite3 embedded database library.
//
// Copyright (c) 2004 Rob Groves. All Rights Reserved. rob.groves@btinternet.com
// 
// Permission to use, copy, modify, and distribute this software and its
// documentation for any purpose, without fee, and without a written
// agreement, is hereby granted, provided that the above copyright notice, 
// this paragraph and the following two paragraphs appear in all copies, 
// modifications, and distributions.
//
// IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT,
// INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST
// PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
// EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE. THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF
// ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". THE AUTHOR HAS NO OBLIGATION
// TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
//
// V3.0		03/08/2004	-Initial Version for sqlite3
//
// V3.1		16/09/2004	-Implemented getXXXXField using sqlite3 functions
//						-Added CppSQLiteDB3::tableExists()
////////////////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "DbSqlite3.h"



// Named constant for passing to CppSQLite3Exception when passing it a string
// that cannot be deleted.
//static const bool DONT_DELETE_MSG=false;

////////////////////////////////////////////////////////////////////////////////
// Prototypes for SQLite functions not included in SQLite DLL, but copied below
// from SQLite encode.c
////////////////////////////////////////////////////////////////////////////////
int sqlite3_encode_binary(const unsigned char *in, int n, unsigned char *out);
int sqlite3_decode_binary(const unsigned char *in, unsigned char *out);





////////////////////////////////////////////////////////////////////////////////

CppSQLite3DB::CppSQLite3DB()
{
	mpDB = 0;
	mnBusyTimeoutMs = 60000; // 60 seconds
}


CppSQLite3DB::CppSQLite3DB(const CppSQLite3DB& db)
{
	mpDB = db.mpDB;
	mnBusyTimeoutMs = 60000; // 60 seconds
}


CppSQLite3DB::~CppSQLite3DB()
{
	close();
}


CppSQLite3DB& CppSQLite3DB::operator=(const CppSQLite3DB& db)
{
	mpDB = db.mpDB;
	mnBusyTimeoutMs = 60000; // 60 seconds
	return *this;
}


void CppSQLite3DB::open(const char* szFile)
{
	int nRet = sqlite3_open(szFile, &mpDB);

	if (nRet != SQLITE_OK)
	{
		const char* szError = sqlite3_errmsg(mpDB);
		throw CDbSqlite3Exception(nRet, (char*)szError, DONT_DELETE_MSG);
	}

	setBusyTimeout(mnBusyTimeoutMs);
}


void CppSQLite3DB::close()
{
	if (mpDB)
	{
		sqlite3_close(mpDB);
		mpDB = 0;
	}
}


CppSQLite3Statement CppSQLite3DB::compileStatement(const char* szSQL)
{
	checkDB();

	sqlite3_stmt* pVM = compile(szSQL);
	return CppSQLite3Statement(mpDB, pVM);
}


bool CppSQLite3DB::tableExists(const char* szTable)
{
	char szSQL[128];
	sprintf_s(szSQL,
			"select count(*) from sqlite_master where type='table' and name='%s'",
			szTable);
	int nRet = execScalar(szSQL);
	return (nRet > 0);
}


int CppSQLite3DB::execDML(const char* szSQL)
{
	checkDB();

	char* szError=0;

	int nRet = sqlite3_exec(mpDB, szSQL, 0, 0, &szError);

	if (nRet == SQLITE_OK)
	{
		return sqlite3_changes(mpDB);
	}
	else
	{
		throw CDbSqlite3Exception(nRet, szError);
	}
}


CppSQLite3Query CppSQLite3DB::execQuery(const char* szSQL)
{
	checkDB();

	sqlite3_stmt* pVM = compile(szSQL);

	int nRet = sqlite3_step(pVM);

	if (nRet == SQLITE_DONE)
	{
		// no rows
		return CppSQLite3Query(mpDB, pVM, true/*eof*/);
	}
	else if (nRet == SQLITE_ROW)
	{
		// at least 1 row
		return CppSQLite3Query(mpDB, pVM, false/*eof*/);
	}
	else
	{
		nRet = sqlite3_finalize(pVM);
		const char* szError= sqlite3_errmsg(mpDB);
		throw CDbSqlite3Exception(nRet, (char*)szError, DONT_DELETE_MSG);
	}
}


int CppSQLite3DB::execScalar(const char* szSQL)
{
	CppSQLite3Query q = execQuery(szSQL);

	if (q.eof() || q.numFields() < 1)
	{
		throw CDbSqlite3Exception(DBSQLITE_ERROR,
								"Invalid scalar query",
								DONT_DELETE_MSG);
	}

	return atoi(q.fieldValue(0));
}


CppSQLite3Table CppSQLite3DB::getTable(const char* szSQL)
{
	checkDB();

	char* szError=0;
	char** paszResults=0;
	int nRet;
	int nRows(0);
	int nCols(0);

	nRet = sqlite3_get_table(mpDB, szSQL, &paszResults, &nRows, &nCols, &szError);

	if (nRet == SQLITE_OK)
	{
		return CppSQLite3Table(paszResults, nRows, nCols);
	}
	else
	{
		throw CDbSqlite3Exception(nRet, szError);
	}
}


sqlite_int64 CppSQLite3DB::lastRowId()
{
	return sqlite3_last_insert_rowid(mpDB);
}


void CppSQLite3DB::setBusyTimeout(int nMillisecs)
{
	mnBusyTimeoutMs = nMillisecs;
	sqlite3_busy_timeout(mpDB, mnBusyTimeoutMs);
}


void CppSQLite3DB::checkDB()
{
	if (!mpDB)
	{
		throw CDbSqlite3Exception(DBSQLITE_ERROR,
								"Database not open",
								DONT_DELETE_MSG);
	}
}


sqlite3_stmt* CppSQLite3DB::compile(const char* szSQL)
{
	checkDB();

	char* szError=0;
	const char* szTail=0;
	sqlite3_stmt* pVM;

	int nRet = sqlite3_prepare(mpDB, szSQL, -1, &pVM, &szTail);

	if (nRet != SQLITE_OK)
	{
		throw CDbSqlite3Exception(nRet, szError);
	}

	return pVM;
}


////////////////////////////////////////////////////////////////////////////////
// SQLite encode.c reproduced here, containing implementation notes and source
// for sqlite3_encode_binary() and sqlite3_decode_binary() 
////////////////////////////////////////////////////////////////////////////////

/*
** 2002 April 25
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This file contains helper routines used to translate binary data into
** a null-terminated string (suitable for use in SQLite) and back again.
** These are convenience routines for use by people who want to store binary
** data in an SQLite database.  The code in this file is not used by any other
** part of the SQLite library.
**
** $Id: encode.c,v 1.10 2004/01/14 21:59:23 drh Exp $
*/

/*
** How This Encoder Works
**
** The output is allowed to contain any character except 0x27 (') and
** 0x00.  This is accomplished by using an escape character to encode
** 0x27 and 0x00 as a two-byte sequence.  The escape character is always
** 0x01.  An 0x00 is encoded as the two byte sequence 0x01 0x01.  The
** 0x27 character is encoded as the two byte sequence 0x01 0x03.  Finally,
** the escape character itself is encoded as the two-character sequence
** 0x01 0x02.
**
** To summarize, the encoder works by using an escape sequences as follows:
**
**       0x00  ->  0x01 0x01
**       0x01  ->  0x01 0x02
**       0x27  ->  0x01 0x03
**
** If that were all the encoder did, it would work, but in certain cases
** it could double the size of the encoded string.  For example, to
** encode a string of 100 0x27 characters would require 100 instances of
** the 0x01 0x03 escape sequence resulting in a 200-character output.
** We would prefer to keep the size of the encoded string smaller than
** this.
**
** To minimize the encoding size, we first add a fixed offset value to each 
** byte in the sequence.  The addition is modulo 256.  (That is to say, if
** the sum of the original character value and the offset exceeds 256, then
** the higher order bits are truncated.)  The offset is chosen to minimize
** the number of characters in the string that need to be escaped.  For
** example, in the case above where the string was composed of 100 0x27
** characters, the offset might be 0x01.  Each of the 0x27 characters would
** then be converted into an 0x28 character which would not need to be
** escaped at all and so the 100 character input string would be converted
** into just 100 characters of output.  Actually 101 characters of output - 
** we have to record the offset used as the first byte in the sequence so
** that the string can be decoded.  Since the offset value is stored as
** part of the output string and the output string is not allowed to contain
** characters 0x00 or 0x27, the offset cannot be 0x00 or 0x27.
**
** Here, then, are the encoding steps:
**
**     (1)   Choose an offset value and make it the first character of
**           output.
**
**     (2)   Copy each input character into the output buffer, one by
**           one, adding the offset value as you copy.
**
**     (3)   If the value of an input character plus offset is 0x00, replace
**           that one character by the two-character sequence 0x01 0x01.
**           If the sum is 0x01, replace it with 0x01 0x02.  If the sum
**           is 0x27, replace it with 0x01 0x03.
**
**     (4)   Put a 0x00 terminator at the end of the output.
**
** Decoding is obvious:
**
**     (5)   Copy encoded characters except the first into the decode 
**           buffer.  Set the first encoded character aside for use as
**           the offset in step 7 below.
**
**     (6)   Convert each 0x01 0x01 sequence into a single character 0x00.
**           Convert 0x01 0x02 into 0x01.  Convert 0x01 0x03 into 0x27.
**
**     (7)   Subtract the offset value that was the first character of
**           the encoded buffer from all characters in the output buffer.
**
** The only tricky part is step (1) - how to compute an offset value to
** minimize the size of the output buffer.  This is accomplished by testing
** all offset values and picking the one that results in the fewest number
** of escapes.  To do that, we first scan the entire input and count the
** number of occurances of each character value in the input.  Suppose
** the number of 0x00 characters is N(0), the number of occurances of 0x01
** is N(1), and so forth up to the number of occurances of 0xff is N(255).
** An offset of 0 is not allowed so we don't have to test it.  The number
** of escapes required for an offset of 1 is N(1)+N(2)+N(40).  The number
** of escapes required for an offset of 2 is N(2)+N(3)+N(41).  And so forth.
** In this way we find the offset that gives the minimum number of escapes,
** and thus minimizes the length of the output string.
*/

/*
** Encode a binary buffer "in" of size n bytes so that it contains
** no instances of characters '\'' or '\000'.  The output is 
** null-terminated and can be used as a string value in an INSERT
** or UPDATE statement.  Use sqlite3_decode_binary() to convert the
** string back into its original binary.
**
** The result is written into a preallocated output buffer "out".
** "out" must be able to hold at least 2 +(257*n)/254 bytes.
** In other words, the output will be expanded by as much as 3
** bytes for every 254 bytes of input plus 2 bytes of fixed overhead.
** (This is approximately 2 + 1.0118*n or about a 1.2% size increase.)
**
** The return value is the number of characters in the encoded
** string, excluding the "\000" terminator.
*/

