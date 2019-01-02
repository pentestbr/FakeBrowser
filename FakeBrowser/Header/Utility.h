#include "nghttp2.h"

#pragma once
#define MAKE_NV(K, V)                                                          \
  {                                                                            \
    (uint8_t *)K, (uint8_t *)V, sizeof(K) - 1, sizeof(V) - 1,                  \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

namespace Utility
{
	//Copy from osprey
	enum punycode_status {
		punycode_success,
		punycode_bad_input,   /* Input is invalid.                       */
		punycode_big_output,  /* Output would exceed the space provided. */
		punycode_overflow     /* Input needs wider integers to process.  */
	};

#if UINT_MAX >= (1 << 26) - 1
	typedef unsigned int punycode_uint;
#else
	typedef unsigned long punycode_uint;
#endif

	enum punycode_status punycode_encode(
		punycode_uint input_length,
		const punycode_uint input[],
		const unsigned char case_flags[],
		punycode_uint *output_length,
		char output[]);

	/*** Bootstring parameters for Punycode ***/

	enum {
		base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700,
		initial_bias = 72, initial_n = 0x80, delimiter = 0x2D
	};


#define PUNY_PREFIX ("xn--")
#define PUNY_PREFIX_LEN (4)

	/* basic(cp) tests whether cp is a basic code point: */
#define basic(cp) ((punycode_uint)(cp) < 0x80)

	/* delim(cp) tests whether cp is a delimiter: */
#define delim(cp) ((cp) == delimiter)

	/* decode_digit(cp) returns the numeric value of a basic code */
	/* point (for use in representing integers) in the range 0 to */
	/* base-1, or base if cp is does not represent a value.       */

	static punycode_uint decode_digit(punycode_uint cp)
	{
		return  cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 :
			cp - 97 < 26 ? cp - 97 : base;
	}

	/* encode_digit(d,flag) returns the basic code point whose value      */
	/* (when used for representing integers) is d, which needs to be in   */
	/* the range 0 to base-1.  The lowercase form is used unless flag is  */
	/* nonzero, in which case the uppercase form is used.  The behavior   */
	/* is undefined if flag is nonzero and digit d has no uppercase form. */

	static char encode_digit(punycode_uint d, int flag)
	{
		return d + 22 + 75 * (d < 26) - ((flag != 0) << 5);
		/*  0..25 map to ASCII a..z or A..Z */
		/* 26..35 map to ASCII 0..9         */
	}

	/* flagged(bcp) tests whether a basic code point is flagged */
	/* (uppercase).  The behavior is undefined if bcp is not a  */
	/* basic code point.                                        */

#define flagged(bcp) ((punycode_uint)(bcp) - 65 < 26)

	/* encode_basic(bcp,flag) forces a basic code point to lowercase */
	/* if flag is zero, uppercase if flag is nonzero, and returns    */
	/* the resulting code point.  The code point is unchanged if it  */
	/* is caseless.  The behavior is undefined if bcp is not a basic */
	/* code point.                                                   */

	static char encode_basic(punycode_uint bcp, int flag)
	{

		bcp -= (bcp - 97 < 26) << 5;
		return bcp + ((!flag && (bcp - 65 < 26)) << 5);
	}

	/*** Platform-specific constants ***/

	/* maxint is the maximum value of a punycode_uint variable: */
	static const punycode_uint maxint = -1;
	/* Because maxint is unsigned, -1 becomes the maximum value. */

	/*** Bias adaptation function ***/
	void GetRandomBytes(uint8_t* pUi8RandomBytes);
	BOOL ParseURLInfo(std::string sUrl, std::string& sProtocol, std::string& sHostName, std::string& sPort, std::string& sPath);
	BOOL ParseURLInfoW(std::wstring wsUrl, std::wstring& wsProtocol, std::wstring& wsHostName, std::wstring& wsPort, std::wstring& wsPath);
	BOOL ConvertURLFromWstring2String(const std::wstring wsUrl, std::string& sUrl);
	BOOL DoEncode(const std::wstring& wide_string, std::string& sUrlEncode);
	BOOL PunycodeEncode(const WCHAR* sDomainName, char** spunycode, DWORD* _pdwWin32ErrorCode);
	BOOL NeedPunycodeW(std::wstring wide_string);
	BOOL ResolveURL(std::string sUrl, addrinfo *&aiResult, char *&pcIp);

	//Copy and modify from nghttp2 https://github.com/nghttp2/nghttp2/blob/master/examples/deflate.c
	void Deflate(const nghttp2_nv *const nva,size_t nvlen, uint8_t* &buf, size_t& outlen, size_t &sum);
	int Inflate(uint8_t *in,size_t inlen, int final);

	__int64 GetTimestamp();
	std::wstring String2Wstring(std::string s);
	template <class T>
	void FreeOBJ(T** obj)
	{
		if (*obj != nullptr) {
			delete[] * obj;
			*obj = nullptr;
		}
	}
	void PrintUsage(_TCHAR** argv);
	void WriteFile(std::string fileName, BYTE* response, size_t recSize);
}

