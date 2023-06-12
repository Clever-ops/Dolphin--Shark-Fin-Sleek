#ifndef  SCRIPT_CONTEXT_IMPL
#define SCRIPT_CONTEXT_IMPL

#include <memory>
#include <mutex>
#include "Core/Scripting/CoreScriptContextFiles/Implementations/InstructionBreakpointsHolder.h"
#include "Core/Scripting/CoreScriptContextFiles/Implementations/MemoryAddressBreakpointsHolder.h"
#include "Core/Scripting/CoreScriptContextFiles/InternalScriptAPIs/ScriptContext_APIs.h"
#include "Core/Scripting/CoreScriptContextFiles/InternalScriptAPIs/ScriptCallLocations.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ScriptContext
{
  void (*print_callback_function)(void*, const char*);
  void (*script_end_callback_function)(void*, int);

  int unique_script_identifier;
  const char* script_filename;
  ScriptCallLocations current_script_call_location;
  int is_script_active;
  int finished_with_global_code;
  int called_yielding_function_in_last_global_script_resume;
  int called_yielding_function_in_last_frame_callback_script_resume;
  std::recursive_mutex script_specific_lock;

  InstructionBreakpointsHolder instructionBreakpointsHolder;
  MemoryAddressBreakpointsHolder memoryAddressBreakpointsHolder;

  DLL_Defined_ScriptContext_APIs dll_specific_api_definitions;

} ScriptContext;

extern const char* most_recent_script_version;

void* ScriptContext_Initializer_impl(int unique_identifier, const char* script_file_name,
                                     void (*print_callback_function)(void*, const char*),
                                     void (*script_end_callback)(void*, int),
                                     void* new_dll_api_definitions);

void ScriptContext_Destructor_impl(void* script_context);
void ScriptContext_ShutdownScript_impl(void* script_context);

typedef void (*PRINT_CALLBACK_TYPE)(void*, const char*);
typedef void (*SCRIPT_END_CALLBACK_TYPE)(void*, int);

PRINT_CALLBACK_TYPE ScriptContext_GetPrintCallback_impl(void*);
SCRIPT_END_CALLBACK_TYPE ScriptContext_GetScriptEndCallback_impl(void*);

const char* ScriptContext_GetScriptFilename_impl(void*);

ScriptCallLocations ScriptContext_GetScriptCallLocation_impl(void*);

int ScriptContext_GetIsScriptActive_impl(void*);
void ScriptContext_SetIsScriptActive_impl(void*, int);

int ScriptContext_GetIsFinishedWithGlobalCode_impl(void*);

void ScriptContext_SetIsFinishedWithGlobalCode_impl(void*, int);


int ScriptContext_GetCalledYieldingFunctionInLastGlobalScriptResume_impl(void*);

void ScriptContext_SetCalledYieldingFunctionInLastGlobalScriptResume_impl(void*, int);


int ScriptContext_GetCalledYieldingFunctionInLastFrameCallbackScriptResume_impl(void*);
void ScriptContext_SetCalledYieldingFunctionInLastFrameCallbackScriptResume_impl(void*, int);

void* ScriptContext_GetInstructionBreakpointsHolder_impl(void*);
void* ScriptContext_GetMemoryAddressBreakpointsHolder_impl(void*);

void* ScriptContext_GetDllDefinedScriptContextApis_impl(void*);

const char* ScriptContext_GetScriptVersion_impl();

#ifdef __cplusplus
}
#endif

#endif
