	
#include <windows.h>
#include <stdio.h>

// those are for Vista though!

typedef struct _KSYSTEM_TIME
{
     ULONG LowPart;
     LONG High1Time;
     LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
         NtProductWinNt = 1,
         NtProductLanManNt = 2,
         NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
         StandardDesign = 0,
         NEC98x86 = 1,
         EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

#if 0
typedef struct _KUSER_SHARED_DATA
{
     ULONG TickCountLowDeprecated;
     ULONG TickCountMultiplier;
     KSYSTEM_TIME InterruptTime;
     KSYSTEM_TIME SystemTime;
     KSYSTEM_TIME TimeZoneBias;
     WORD ImageNumberLow;
     WORD ImageNumberHigh;
     WCHAR NtSystemRoot[260];
     ULONG MaxStackTraceDepth;
     ULONG CryptoExponent;
     ULONG TimeZoneId;
     ULONG LargePageMinimum;
     ULONG Reserved2[7];
     NT_PRODUCT_TYPE NtProductType;
     UCHAR ProductTypeIsValid;
     ULONG NtMajorVersion;
     ULONG NtMinorVersion;
     UCHAR ProcessorFeatures[64];
     ULONG Reserved1;
     ULONG Reserved3;
     ULONG TimeSlip;
     ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
     LARGE_INTEGER SystemExpirationDate;
     ULONG SuiteMask;
     UCHAR KdDebuggerEnabled;
     UCHAR NXSupportPolicy;
     ULONG ActiveConsoleId;
     ULONG DismountCount;
     ULONG ComPlusPackage;
     ULONG LastSystemRITEventTickCount;
     ULONG NumberOfPhysicalPages;
     UCHAR SafeBootMode;
     ULONG SharedDataFlags;
     ULONG DbgErrorPortPresent: 1;
     ULONG DbgElevationEnabled: 1;
     ULONG DbgVirtEnabled: 1;
     ULONG DbgInstallerDetectEnabled: 1;
     ULONG SystemDllRelocated: 1;
     ULONG SpareBits: 27;
     UINT64 TestRetInstruction;
     ULONG SystemCall;
     ULONG SystemCallReturn;
     UINT64 SystemCallPad[3];
     union
     {
          KSYSTEM_TIME TickCount;
          UINT64 TickCountQuad;
     };
     ULONG Cookie;
     INT64 ConsoleSessionForegroundProcessId;
     ULONG Wow64SharedInformation[16];
     WORD UserModeGlobalLogger[8];
     ULONG HeapTracingPid[2];
     ULONG CritSecTracingPid[2];
     ULONG ImageFileExecutionOptions;
     union
     {
          UINT64 AffinityPad;
          ULONG ActiveProcessorAffinity;
     };
     UINT64 InterruptTimeBias;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#else
#define PROCESSOR_FEATURE_MAX 64

typedef struct _KUSER_SHARED_DATA {
  ULONG                         TickCountLowDeprecated;
  ULONG                         TickCountMultiplier;
  KSYSTEM_TIME                  InterruptTime;
  KSYSTEM_TIME                  SystemTime;
  KSYSTEM_TIME                  TimeZoneBias;
  USHORT                        ImageNumberLow;
  USHORT                        ImageNumberHigh;
  WCHAR                         NtSystemRoot[260];
  ULONG                         MaxStackTraceDepth;
  ULONG                         CryptoExponent;
  ULONG                         TimeZoneId;
  ULONG                         LargePageMinimum;
  ULONG                         AitSamplingValue;
  ULONG                         AppCompatFlag;
  ULONGLONG                     RNGSeedVersion;
  ULONG                         GlobalValidationRunlevel;
  LONG                          TimeZoneBiasStamp;
  ULONG                         NtBuildNumber;
  NT_PRODUCT_TYPE               NtProductType;
  BOOLEAN                       ProductTypeIsValid;
  BOOLEAN                       Reserved0[1];
  USHORT                        NativeProcessorArchitecture;
  ULONG                         NtMajorVersion;
  ULONG                         NtMinorVersion;
  BOOLEAN                       ProcessorFeatures[PROCESSOR_FEATURE_MAX];
  ULONG                         Reserved1;
  ULONG                         Reserved3;
  ULONG                         TimeSlip;
  ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
  ULONG                         BootId;
  LARGE_INTEGER                 SystemExpirationDate;
  ULONG                         SuiteMask;
  BOOLEAN                       KdDebuggerEnabled;
  union {
    UCHAR MitigationPolicies;
    struct {
      UCHAR NXSupportPolicy : 2;
      UCHAR SEHValidationPolicy : 2;
      UCHAR CurDirDevicesSkippedForDlls : 2;
      UCHAR Reserved : 2;
    };
  };
  USHORT                        CyclesPerYield;
  ULONG                         ActiveConsoleId;
  ULONG                         DismountCount;
  ULONG                         ComPlusPackage;
  ULONG                         LastSystemRITEventTickCount;
  ULONG                         NumberOfPhysicalPages;
  BOOLEAN                       SafeBootMode;
  UCHAR                         VirtualizationFlags;
  UCHAR                         Reserved12[2];
  union {
    ULONG SharedDataFlags;
    struct {
      ULONG DbgErrorPortPresent : 1;
      ULONG DbgElevationEnabled : 1;
      ULONG DbgVirtEnabled : 1;
      ULONG DbgInstallerDetectEnabled : 1;
      ULONG DbgLkgEnabled : 1;
      ULONG DbgDynProcessorEnabled : 1;
      ULONG DbgConsoleBrokerEnabled : 1;
      ULONG DbgSecureBootEnabled : 1;
      ULONG DbgMultiSessionSku : 1;
      ULONG DbgMultiUsersInSessionSku : 1;
      ULONG DbgStateSeparationEnabled : 1;
      ULONG SpareBits : 21;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME2;
  ULONG                         DataFlagsPad[1];
  ULONGLONG                     TestRetInstruction;
  LONGLONG                      QpcFrequency;
  ULONG                         SystemCall;
  union {
    ULONG AllFlags;
    struct {
      ULONG Win32Process : 1;
      ULONG Sgx2Enclave : 1;
      ULONG VbsBasicEnclave : 1;
      ULONG SpareBits : 29;
    };
  } UserCetAvailableEnvironments;
  ULONGLONG                     SystemCallPad[2];
  union {
    KSYSTEM_TIME TickCount;
    ULONG64      TickCountQuad;
    struct {
      ULONG ReservedTickCountOverlay[3];
      ULONG TickCountPad[1];
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME3;
  ULONG                         Cookie;
  ULONG                         CookiePad[1];
  LONGLONG                      ConsoleSessionForegroundProcessId;
  ULONGLONG                     TimeUpdateLock;
  ULONGLONG                     BaselineSystemTimeQpc;
  ULONGLONG                     BaselineInterruptTimeQpc;
  ULONGLONG                     QpcSystemTimeIncrement;
  ULONGLONG                     QpcInterruptTimeIncrement;
  UCHAR                         QpcSystemTimeIncrementShift;
  UCHAR                         QpcInterruptTimeIncrementShift;
  USHORT                        UnparkedProcessorCount;
  ULONG                         EnclaveFeatureMask[4];
  ULONG                         TelemetryCoverageRound;
  USHORT                        UserModeGlobalLogger[16];
  ULONG                         ImageFileExecutionOptions;
  ULONG                         LangGenerationCount;
  ULONGLONG                     Reserved4;
  ULONGLONG                     InterruptTimeBias;
  ULONGLONG                     QpcBias;
  ULONG                         ActiveProcessorCount;
  UCHAR                         ActiveGroupCount;
  UCHAR                         Reserved9;
  union {
    USHORT QpcData;
    struct {
      UCHAR QpcBypassEnabled;
      UCHAR QpcShift;
    };
  };
  LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
  LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
  XSTATE_CONFIGURATION          XState;
  KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
  ULONG                         Spare;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#endif

typedef NTSTATUS (NTAPI *_RtlQueryElevationFlags)(DWORD* pFlags);

int main() {
    _RtlQueryElevationFlags RtlQueryElevationFlags =
        (_RtlQueryElevationFlags)GetProcAddress(
            LoadLibraryA("ntdll.dll"), "RtlQueryElevationFlags");

    PKUSER_SHARED_DATA kpage = (PKUSER_SHARED_DATA)0x7ffe0000;;
    wprintf(L"%s\n", kpage->NtSystemRoot);
    printf("%u %u\n", kpage->NtMajorVersion, kpage->NtMinorVersion);
    printf("%x\n", kpage->KdDebuggerEnabled);

    printf("%x\n", kpage->DbgErrorPortPresent);
    printf("%x\n", kpage->DbgElevationEnabled);
    printf("%x\n", kpage->DbgVirtEnabled);
    printf("%x\n", kpage->DbgInstallerDetectEnabled);

    printf("scozzerdone\n");

    DWORD pFlags;
    RtlQueryElevationFlags(&pFlags);
    printf("RTL output: %x\n", pFlags);

    return 0;
}