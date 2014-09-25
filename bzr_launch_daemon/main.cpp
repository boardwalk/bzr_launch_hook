#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>
#include <stdexcept>
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
   try
   {
      HINSTANCE hookLib = LoadLibrary(TEXT("bzr_launch_hook.dll"));

      if(hookLib == NULL)
      {
         throw runtime_error("LoadLibrary failed");
      }

      WINEVENTPROC eventHookProc = reinterpret_cast<WINEVENTPROC>(GetProcAddress(hookLib, "_WinEventProc@28"));

      if(eventHookProc == NULL)
      {
         throw runtime_error("GetProcAddress failed");
      }

      HWINEVENTHOOK eventHook = SetWinEventHook(EVENT_MIN, EVENT_MAX, hookLib, eventHookProc, 0, 0, WINEVENT_INCONTEXT);

      if(eventHookProc == 0)
      {
         throw runtime_error("SetWinEventHook failed");
      }

      cout << "Hook set, press enter to exit" << endl;
      getchar();

      UnhookWinEvent(eventHook);
      FreeLibrary(hookLib);
   }
   catch(runtime_error& e)
   {
      cerr << "An error occurred: " << e.what() << endl;
      return EXIT_FAILURE;
   }

   return EXIT_SUCCESS;
}