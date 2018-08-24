// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 VIRTUALMACHINECHECK_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// VIRTUALMACHINECHECK_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef VIRTUALMACHINECHECK_EXPORTS
#define VIRTUALMACHINECHECK_API EXTERN_C __declspec(dllexport)
#else
#define VIRTUALMACHINECHECK_API EXTERN_C __declspec(dllimport)
#endif

#include "GetHostDiskInfo.h"
#include "GetVirtualMachineInfo.h"
#include "../Common/Funcs.h"


#define VL_MAGIC_NUMBER (0x23E72DAC)

VIRTUALMACHINECHECK_API int VirtualCheck(const int magic, const char* checkExt,const char* virtualFileDir,const char* CheckvirtualFileDir, PFCallbackVirtualMachine VirtualFile);

VIRTUALMACHINECHECK_API int VirtualInternetRecordCheck(const int magic, const char* recordFilePath, const char* virtualFileDir,const char* CheckvirtualFileDir
	, PFCallbackVirtualInternetRecord VirtualRecord);
