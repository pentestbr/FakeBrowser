#include "stdafx.h"
#include <Windows.h>
#include <algorithm>
#include <iterator>
#include <chrono>
#include <time.h>
#include <regex>
#include <fstream>
#include <ws2tcpip.h>

#include "Utility.h"

namespace Utility
{
	__int64 GetTimestamp()
	{
		__int64 now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		return now;
	}

	void GetRandomBytes(uint8_t* pUi8RandomBytes)
	{
		/*htonl The htonl function converts a u_long from host to TCP/IP network byte order (which is big-endian).
		https://msdn.microsoft.com/zh-tw/library/windows/desktop/ms738556(v=vs.85).aspx */
		__int64 timestamp = htonl(GetTimestamp());
		memcpy(pUi8RandomBytes, (uint8_t*)&timestamp, 4);

		int iSecret, iGuess;

		/* initialize random seed: */
		srand(time(NULL));

		/* generate 28 random bytes: */
		for (int i = 0; i != 28; ++i) {
			iSecret = rand() % 255;
			memcpy(pUi8RandomBytes + (i + 4), (uint8_t*)&iSecret, 1);
		}
	}

	std::wstring String2Wstring(std::string s)
	{
		int len;
		int slength = (int)s.length() + 1;
		len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
		wchar_t* buf = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
		std::wstring r(buf);
		Utility::FreeOBJ(&buf);
		return r;
	}

	static punycode_uint adapt(
		punycode_uint delta, punycode_uint numpoints, int firsttime)
	{
		punycode_uint k;

		delta = firsttime ? delta / damp : delta >> 1;
		/* delta >> 1 is a faster way of doing delta / 2 */
		delta += delta / numpoints;

		for (k = 0; delta > ((base - tmin) * tmax) / 2; k += base) {
			delta /= base - tmin;
		}

		return k + (base - tmin + 1) * delta / (delta + skew);
	}

	enum punycode_status punycode_encode(
		punycode_uint input_length,
		const punycode_uint input[],
		const unsigned char case_flags[],
		punycode_uint *output_length,
		char output[])
	{
		punycode_uint n, delta, h, b, out, max_out, bias, j, m, q, k, t;

		/* Initialize the state: */

		n = initial_n;
		delta = out = 0;
		max_out = *output_length;
		bias = initial_bias;

		/* Handle the basic code points: */

		for (j = 0; j < input_length; ++j) {
			if (basic(input[j])) {
				if (max_out - out < 2) return punycode_big_output;
				output[out++] =
					case_flags ? encode_basic(input[j], case_flags[j]) : input[j];
			}
			/* else if (input[j] < n) return punycode_bad_input; */
			/* (not needed for Punycode with unsigned code points) */
		}

		h = b = out;

		/* h is the number of code points that have been handled, b is the  */
		/* number of basic code points, and out is the number of characters */
		/* that have been output.                                           */

		if (b > 0) output[out++] = delimiter;

		/* Main encoding loop: */

		while (h < input_length) {
			/* All non-basic code points < n have been     */
			/* handled already.  Find the next larger one: */

			for (m = maxint, j = 0; j < input_length; ++j) {
				/* if (basic(input[j])) continue; */
				/* (not needed for Punycode) */
				if (input[j] >= n && input[j] < m) m = input[j];
			}

			/* Increase delta enough to advance the decoder's    */
			/* <n,i> state to <m,0>, but guard against overflow: */

			if (m - n > (maxint - delta) / (h + 1)) return punycode_overflow;
			delta += (m - n) * (h + 1);
			n = m;

			for (j = 0; j < input_length; ++j) {
				/* Punycode does not need to check whether input[j] is basic: */
				if (input[j] < n /* || basic(input[j]) */) {
					if (++delta == 0) return punycode_overflow;
				}

				if (input[j] == n) {
					/* Represent delta as a generalized variable-length integer: */

					for (q = delta, k = base; ; k += base) {
						if (out >= max_out) return punycode_big_output;

						t = k <= bias /* + tmin */ ? tmin :     /* +tmin not needed */
							k >= bias + tmax ? tmax : k - bias;
						if (q < t) break;
						output[out++] = encode_digit(t + (q - t) % (base - t), 0);
						q = (q - t) / (base - t);
					}

					output[out++] = encode_digit(q, case_flags && case_flags[j]);
					bias = adapt(delta, h + 1, h == b);
					delta = 0;
					++h;
				}
			}

			++delta, ++n;
		}

		*output_length = out;
		return punycode_success;
	}

	BOOL ParseURLInfo(std::string sUrl, std::string& sProtocol, std::string& sHostName, std::string& sPort, std::string& sPath)
	{
		std::regex reg("^.*?([^\:]+)\:\/\/([^\/]+)");
		std::regex regPort("^.*?([^\:]+)\:([^\/]+)");
		std::regex regPath("^.*?[^\:]+\:\/\/[^\/]+(\/[^$]+)");
		std::smatch base_match;

		std::regex_search(sUrl, base_match, reg);
		sProtocol = base_match[1];
		sHostName = base_match[2];
		if (sHostName == "") {
			printf("Invalid url format: %s", sUrl.c_str());
			return FALSE;
		}

		std::regex_search(sUrl, base_match, regPath);
		sPath = base_match[1];
		if (sPath == "")
			sPath = "/";

		std::regex_search(sHostName, base_match, regPort);
		if (base_match[1] != "")
			sHostName = base_match[1];
		sPort = base_match[2];

		if (sPort == "") {
			if (sProtocol == "https" || sProtocol == "wss") {
				sPort = "443";
			}
			else if (sProtocol == "http" || sProtocol == "ws") {
				sPort = "80";
			}
			else if (sProtocol == "socks4" || sProtocol == "socks5") {
				sPort = "1080";
			}
		}

		/*if(NeedPunycodeW(hostName))
			DoEncode(hostName);*/

		return TRUE;
	}

	BOOL ParseURLInfoW(std::wstring wsUrl, std::wstring& wsProtocol, std::wstring& wsHostName, std::wstring& wsPort, std::wstring& wsPath)
	{
		std::wregex reg(L"^.*?([^\:]+)\:\/\/([^\/]+)");
		std::wregex regPort(L"^.*?([^\:]+)\:([^\/]+)");
		std::wregex regPath(L"^.*?[^\:]+\:\/\/[^\/]+(\/[^$]+)");
		std::wsmatch base_match;

		std::regex_search(wsUrl, base_match, reg);
		wsProtocol = base_match[1];
		wsHostName = base_match[2];
		if (wsHostName == L"") {
			wprintf(L"Invalid url format: %s", wsUrl.c_str());
			return FALSE;
		}

		std::regex_search(wsUrl, base_match, regPath);
		wsPath = base_match[1];
		if (wsPath == L"")
			wsPath = L"/";

		std::regex_search(wsHostName, base_match, regPort);
		if (base_match[1] != L"")
			wsHostName = base_match[1];
		wsPort = base_match[2];

		if (wsPort == L"") {
			if (wsProtocol == L"https") {
				wsPort = L"443";
			}
			else if (wsProtocol == L"http") {
				wsPort = L"80";
			}
			else if (wsProtocol == L"socks4" || wsProtocol == L"socks5") {
				wsPort = L"1080";
			}
		}

		return TRUE;
	}

	BOOL ConvertURLFromWstring2String(const std::wstring wsUrl, std::string& sUrl)
	{
		if (!NeedPunycodeW(wsUrl)) {
			sUrl = std::string(wsUrl.begin(), wsUrl.end());
			return TRUE;
		}

		std::wstring wsProtocol, wsHostName, wsPort, wsPath;
		std::string sProtocol, sHostName, sPath, sPort;
		if (!ParseURLInfoW(wsUrl, wsProtocol, wsHostName, wsPort, wsPath) || 
			!DoEncode(wsHostName, sHostName)) {
			return FALSE;
		}

		sProtocol = std::string(wsProtocol.begin(), wsProtocol.end());
		sPath = std::string(wsPath.begin(), wsPath.end());
		sPort = std::string(wsPort.begin(), wsPort.end());
		sUrl = sProtocol + "://" + sHostName + ":" + sPort + sPath;
		return TRUE;
	}

	BOOL DoEncode(const std::wstring& wide_string, std::string& sUrlEncode)
	{
		//std::wstring wide_string = String2Wstring(hostName);
		const WCHAR* sDomainName = wide_string.c_str();
		DWORD* _pdwWin32ErrorCode = NULL;
		//parser DomainName
		bool bRet = FALSE;
		size_t nLen = wcslen(sDomainName);
		WCHAR* pPtr = (WCHAR*)sDomainName;
		WCHAR* pStart = pPtr;
		WCHAR* pEnd = pPtr + nLen;
		WCHAR* wSub = new WCHAR[nLen + 2];
		WCHAR* pSub = wSub;
		size_t nSubLen = 0;
		std::string sOutput;
		std::string sSub;
		char* spunycode_sub = NULL;
		bool IsNeedPunycode = FALSE;

		do
		{
			//Find separate sign
			if ((*pPtr == L'.') || (*pPtr == L'@') || (*pPtr == L':') || (pPtr == pEnd))
			{

				nSubLen = pPtr - pStart;//or nSubLen++ after pPtr++

				if (IsNeedPunycode)
				{
					//Do puny code
					*pSub = 0;
					spunycode_sub = NULL;
					bRet = PunycodeEncode(wSub, &spunycode_sub, _pdwWin32ErrorCode);
					if ((!bRet) || (NULL == spunycode_sub))
					{
						Utility::FreeOBJ(&wSub);
						if (spunycode_sub)
							Utility::FreeOBJ(&spunycode_sub);
						return FALSE;
					}
					sOutput += PUNY_PREFIX;
					sOutput += spunycode_sub;
					Utility::FreeOBJ(&spunycode_sub);
					sSub.clear();
				}

				if (pPtr != pEnd)
					sSub.append(1, (char)*pPtr);

				sOutput += sSub;
				pStart = pPtr + 1;
				pSub = wSub;
				nSubLen = 0;
				sSub.clear();
				IsNeedPunycode = FALSE;
			}
			else
			{
				sSub.append(1, (char)*pPtr);
				*pSub = *pPtr;
				pSub++;
			}

			if (*pPtr >= initial_n)
			{
				IsNeedPunycode = TRUE;
			}

			pPtr++;
		} while (pPtr <= pEnd);

		char* sTemp = new char[sOutput.length() + 1];
		//strcpy(sTemp,sOutput.c_str());
		::strncpy_s(sTemp, sOutput.length() + 1, sOutput.c_str(), _TRUNCATE);
		sUrlEncode.assign(sTemp);

		return TRUE;
	}

	BOOL PunycodeEncode(const WCHAR* sDomainName, char** spunycode, DWORD* _pdwWin32ErrorCode)
	{
		if ((NULL == sDomainName) || (NULL == spunycode))
		{
			if (_pdwWin32ErrorCode)
				*_pdwWin32ErrorCode = ERROR_INVALID_PARAMETER;
			return FALSE;
		}

		enum punycode_status status;
		punycode_uint input_length;
		punycode_uint output_length;
		unsigned char* case_flags = NULL;
		punycode_uint* input = NULL;
		char* output = NULL;
		bool bRet = FALSE;

		input_length = (punycode_uint)wcslen(sDomainName);
		output_length = input_length * 4 + 1;
		input = new punycode_uint[input_length];
		case_flags = new unsigned char[input_length];
		output = new char[output_length];


		if ((NULL == case_flags) || (NULL == input) || (NULL == output))
		{
			if (_pdwWin32ErrorCode)
				*_pdwWin32ErrorCode = ERROR_OUTOFMEMORY;
			if (input)
				Utility::FreeOBJ(&input);
			if (case_flags)
				Utility::FreeOBJ(&case_flags);
			if (output)
				Utility::FreeOBJ(&output);
			return FALSE;
		}

		WCHAR* pInput = (WCHAR*)sDomainName;
		ZeroMemory(case_flags, input_length);
		for (unsigned int i = 0; i<input_length; i++) {
			input[i] = pInput[i];
			if (pInput[i] >= 'A'&&pInput[i] <= 'Z')
				case_flags[i] = 1;
		}

		ZeroMemory(output, output_length);
		status = punycode_encode(input_length, input, case_flags,
			&output_length, output);
		if ((status == punycode_success) && (output_length>0))
		{
			if (_pdwWin32ErrorCode)
				*_pdwWin32ErrorCode = ERROR_SUCCESS;
			*spunycode = output;

			bRet = TRUE;
			output = NULL;
		}
		else if (status == punycode_bad_input)
		{
			if (_pdwWin32ErrorCode)
				*_pdwWin32ErrorCode = ERROR_INVALID_PARAMETER;
		}
		else if (status == punycode_big_output)
		{
			if (_pdwWin32ErrorCode)
				*_pdwWin32ErrorCode = ERROR_OUTOFMEMORY;
		}
		else if (status == punycode_overflow)
		{
			if (_pdwWin32ErrorCode)
				*_pdwWin32ErrorCode = ERROR_BUFFER_OVERFLOW;
		}
		else
		{
			if (_pdwWin32ErrorCode)
				*_pdwWin32ErrorCode = ERROR_FLOPPY_UNKNOWN_ERROR;
		}

		if (input)
			Utility::FreeOBJ(&input);
		if (case_flags)
			Utility::FreeOBJ(&case_flags);
		if (output)
			Utility::FreeOBJ(&output);

		return bRet;
	}

	BOOL NeedPunycodeW(std::wstring wide_string)
	{
		//std::wstring wide_string = String2Wstring(hostName);
		const WCHAR* sDomainName = wide_string.c_str();
		//Find DomainName from http:// DomainName / 
		//If all characters in DomainName are smaller then 0x80 then this string doesn't need to do punycode
		if (NULL == sDomainName)
			return FALSE;

		size_t nLen = wcslen(sDomainName);
		for (size_t i = 0; i < nLen; i++)
		{
			if (sDomainName[i] >= initial_n)
			{
				return TRUE;
			}
			else if (sDomainName[i] == L'/')
			{

				//Check is '://' or '/'
				if ((i>0) && (i + 1<nLen))
				{
					if ((sDomainName[i - 1] == L':') && (sDomainName[i + 1] == L'/'))
						i++;//next one is '/' more to next one.
					else
						return FALSE;//find '/'
				}
				else
					return FALSE;//find '/'

			}

		}
		return FALSE;
	}

	int Inflate(uint8_t *in,
		size_t inlen, int final) {
		ssize_t rv;
		nghttp2_hd_inflater *inflater;

		rv = nghttp2_hd_inflate_new(&inflater);

		for (;;) {
			nghttp2_nv nv;
			int inflate_flags = 0;
			size_t proclen;

			rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, in, inlen, final);

			if (rv < 0) {
				fprintf(stderr, "inflate failed with error code %zd", rv);
				return -1;
			}

			proclen = (size_t)rv;

			in += proclen;
			inlen -= proclen;

			if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
				fwrite(nv.name, 1, nv.namelen, stderr);
				fprintf(stderr, ": ");
				fwrite(nv.value, 1, nv.valuelen, stderr);
				fprintf(stderr, "\n");
			}

			if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
				nghttp2_hd_inflate_end_headers(inflater);
				break;
			}

			if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
				break;
			}
		}

		return 0;
	}

	void Deflate(const nghttp2_nv *const nva,
		size_t nvlen, uint8_t* &buf, size_t& outlen, size_t &sum) 
	{
		nghttp2_hd_deflater *deflater;
		/* Define 1st header set.  This is looks like a HTTP request. */
		ssize_t rv;
		//uint8_t *buf;
		size_t buflen;
		//size_t outlen;
		size_t i;
		//size_t sum;

		sum = 0;

		rv = nghttp2_hd_deflate_new(&deflater, 4096);

		if (rv != 0) {
			fprintf(stderr, "nghttp2_hd_deflate_init failed with error: %s\n",
				nghttp2_strerror(rv));
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < nvlen; ++i) {
			sum += nva[i].namelen + nva[i].valuelen;
		}

		printf("Input (%zu byte(s)):\n\n", sum);

		for (i = 0; i < nvlen; ++i) {
			fwrite(nva[i].name, 1, nva[i].namelen, stdout);
			printf(": ");
			fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
			printf("\n");
		}

		buflen = nghttp2_hd_deflate_bound(deflater, nva, nvlen);
		buf = (uint8_t*)malloc(buflen);

		rv = nghttp2_hd_deflate_hd(deflater, buf, buflen, nva, nvlen);

		if (rv < 0) {
			fprintf(stderr, "nghttp2_hd_deflate_hd() failed with error: %s\n",
				nghttp2_strerror((int)rv));

			free(buf);

			exit(EXIT_FAILURE);
		}

		outlen = (size_t)rv;

		printf("\nDeflate (%zu byte(s), ratio %.02f):\n\n", outlen,
			sum == 0 ? 0 : (double)outlen / (double)sum);

		for (size_t i = 0; i < outlen; ++i) {
			if ((i & 0x0fu) == 0) {
				printf("%08zX: ", i);
			}

			printf("%02X ", buf[i]);

			if (((i + 1) & 0x0fu) == 0) {
				printf("\n");
			}
		}
		/*
		printf("\nDeflate (%zu byte(s), ratio %.02f):\n\n", outlen,
		sum == 0 ? 0 : (double)outlen / (double)sum);

		for (i = 0; i < outlen; ++i) {
		if ((i & 0x0fu) == 0) {
		printf("%08zX: ", i);
		}

		printf("%02X ", buf[i]);

		if (((i + 1) & 0x0fu) == 0) {
		printf("\n");
		}
		}*/

		//printf("\n\nInflate:\n\n");

		/* We pass 1 to final parameter, because buf contains whole deflated
		header data. */
		//rv = inflate_header_block(inflater, buf, outlen, 1);

		//if (rv != 0) {
		//	free(buf);

		//	exit(EXIT_FAILURE);
		//}

		//printf("\n-----------------------------------------------------------"
		//	"--------------------\n");

		//free(buf);
	}

	void PrintUsage(_TCHAR** argv)
	{
		wprintf(L"Usage:\n%s\n[-t browser] e.g. chrome,edge,ie,firefox (if the fake browser has been renamed to the specific browser(chrome.exe), this parameter can be ignored)\n"
			"[-u url] The url you want to browse\n"
			"[-f file name] (option) Let tool read the file that contains the url\n"
			"[-p proxy] (option) Only supoort socks4 and socks5\n"
			"[-s] (option) Let fake edge sent two request in the same packet\n"
			"[-o output] (option) Export the response to the specific folder, default will in the same folder with the tool\n", argv[0]);
	}

	void WriteFile(std::string fileName, BYTE* response, size_t recSize)
	{
		if (!recSize)
			return;

		printf("%s", response);

		std::ofstream out(fileName, std::ios::out);
		if (out.is_open())
		{
			out.write((const char*)response, recSize);
			out.close();
		}
	}

	BOOL ResolveURL(std::string sUrl, addrinfo *&aiResult, char *&pcIp)
	{
		std::string sHostName, sPort;
		Utility::ParseURLInfo(sUrl, std::string(), sHostName, sPort, std::string());

		struct addrinfo *p = NULL,
			hints;
		int iResult;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// Resolve the server address and port
		iResult = getaddrinfo(sHostName.c_str(), sPort.c_str(), &hints, &aiResult);
		if (iResult != 0) {
			printf("\n\ngetaddrinfo failed: %s\n", sHostName.c_str());
			WSACleanup();
			return FALSE;
		}

		// Attempt to connect to the first address returned by
		// the call to getaddrinfo
		char ipstr[INET_ADDRSTRLEN];
		for (p = aiResult; p != NULL; p = p->ai_next) {
			struct in_addr  *addr;
			if (p->ai_family == AF_INET) {
				struct sockaddr_in *ipv = (struct sockaddr_in *)p->ai_addr;
				addr = &(ipv->sin_addr);
			}
			else {
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
				addr = (struct in_addr *) &(ipv6->sin6_addr);
			}
			inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
		}

		memcpy(pcIp, ipstr, sizeof(ipstr));

		return TRUE;
	}
}