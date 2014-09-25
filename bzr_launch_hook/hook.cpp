#include "hook.h"
#include <tchar.h>

#define MakePtr(cast, ptr, addValue) (cast)((DWORD)(ptr)+(DWORD)(addValue))

static PIMAGE_IMPORT_DESCRIPTOR getNamedImportDescriptor(HMODULE hModule, const char* szImportMod)
{
    PIMAGE_DOS_HEADER pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);

    // Get the PE header.
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDOSHeader, pDOSHeader->e_lfanew);

    // If there is no imports section, leave now.
    if(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == NULL)
        return NULL;

    // Get the pointer to the imports section.
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = MakePtr (PIMAGE_IMPORT_DESCRIPTOR, pDOSHeader,
       pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Loop through the import module descriptors looking for the
    //  module whose name matches szImportMod.
    for(; pImportDesc->Name != NULL; ++pImportDesc)
    {
        PSTR szCurrMod = MakePtr(PSTR, pDOSHeader, pImportDesc->Name);
        if(_stricmp(szCurrMod, szImportMod) == 0)
            // Found it.
            break;
    }

    // If the name is NULL, then the module is not imported.
    if(pImportDesc->Name == NULL)
        return NULL;

    // All OK, Jumpmaster!
    return pImportDesc;
}

void hookFunctions(cHookDescriptor* pHook, DWORD nCount)
{
   HMODULE hModule = GetModuleHandle(NULL);

   for(cHookDescriptor* i = pHook; i != pHook + nCount; ++i)
   {
      // Get the specific import descriptor.
      PIMAGE_IMPORT_DESCRIPTOR pImportDesc = getNamedImportDescriptor(hModule, i->m_szModule);

      if(pImportDesc == NULL)
         continue;

      // Get the original thunk information for this DLL.  I cannot use
      //  the thunk information stored in the pImportDesc->FirstThunk
      //  because the that is the array that the loader has already
      //  bashed to fix up all the imports.  This pointer gives us acess
      //  to the function names.
      PIMAGE_THUNK_DATA pOrigThunk = MakePtr(PIMAGE_THUNK_DATA, hModule, pImportDesc->OriginalFirstThunk);

      // Get the array pointed to by the pImportDesc->FirstThunk.  This is
      //  where I will do the actual bash.
      PIMAGE_THUNK_DATA pRealThunk = MakePtr(PIMAGE_THUNK_DATA, hModule, pImportDesc->FirstThunk);

      // Loop through and look for the one that matches the name.
      for(; pOrigThunk->u1.Function != NULL; ++pOrigThunk, ++pRealThunk)
      {
         if(i->m_addr == eByName)
         {
            if(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
               // Import must be by name
               continue;

            // Get the name of this imported function.
            PIMAGE_IMPORT_BY_NAME pByName = MakePtr(PIMAGE_IMPORT_BY_NAME, hModule, pOrigThunk->u1.AddressOfData);

            // If the name starts with NULL, then just skip out now.
            if(pByName->Name[0] == '\0')
               continue;

            if(strcmp(pByName->Name, i->m_szFunction) != 0)
               // Name does not match
               continue;
         }
         else
         {
            if(!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
               // The import must be by ordinal
               continue;

            if((pOrigThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG) != i->m_dwOrdinal)
               // Ordinal does not match
               continue;
         }

         // I found it.  Now I need to change the protection to
         //  writable before I do the blast.  Note that I am now
         //  blasting into the real thunk area!
         MEMORY_BASIC_INFORMATION mbi_thunk;

         VirtualQuery(pRealThunk, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION));
         VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, PAGE_READWRITE, &mbi_thunk.Protect);

         // Save the original address if requested.
         i->m_pOldFunction = pRealThunk->u1.Function;
         pRealThunk->u1.Function = i->m_pNewFunction;

         // TEMPORARY
         TCHAR dumb[256];
         _stprintf(dumb, _T("m_pOldFunction=%08x m_pNewFunction=%08x\n"), i->m_pOldFunction, i->m_pNewFunction);
         MessageBox(NULL, dumb, _T("BLOOOP"), MB_OK);

         DWORD dwOldProtect;
         VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, mbi_thunk.Protect, &dwOldProtect);

         break;
      }
   }
}
