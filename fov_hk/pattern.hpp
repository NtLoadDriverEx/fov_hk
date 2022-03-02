#pragma once

#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

inline unsigned char* FindPattern(unsigned char* rangeStart, unsigned char* rangeEnd, const char* pattern)
{
	const unsigned char* pat = reinterpret_cast<const unsigned char*>(pattern);
	unsigned char* firstMatch = 0;
	for (unsigned char* pCur = rangeStart; pCur < rangeEnd; ++pCur)
	{
		if (*(unsigned char*)pat == (unsigned char)'\?' || *pCur == getByte(pat))
		{
			if (!firstMatch)
			{
				firstMatch = pCur;
			}
			pat += (*(unsigned short*)pat == (unsigned short)'\?\?' || *(unsigned char*)pat != (unsigned char)'\?') ? 3 : 2;
			if (!*pat)
			{
				return firstMatch;
			}
		}
		else if (firstMatch)
		{
			pCur = firstMatch;
			pat = reinterpret_cast<const unsigned char*>(pattern);
			firstMatch = 0;
		}
	}
	return 0;
}
