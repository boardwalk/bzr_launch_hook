#ifndef BZRLH_HOOK_H
#define BZRLH_HOOK_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

enum eAddressing
{
   eByName,
   eByOrdinal
};

struct cHookDescriptor
{
   eAddressing m_addr;
   const char* m_szModule;
   const char* m_szFunction;
   DWORD m_dwOrdinal;
   DWORD m_pNewFunction;
   DWORD m_pOldFunction;
};

size_t hookFunctions(cHookDescriptor* pHooks, size_t count);

#endif