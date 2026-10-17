// Read-only retail 17559 XAM-to-kernel contract audit.
// @category Xbox360.XAM
// The embedded usage snapshot is a 2026-10-17 XAM reference export, not a
// live recount. All Ghidra program and linked kernel metadata is preserved.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class AuditXam17559LinkedKernelContracts_20261017_v1 extends GhidraScript {
    private static final String XAM_SHA = "78b3dbd8ae866f4258f5444205486ea9f8451afaa30f469c875dcf345f828467";
    private static final String KERNEL_SHA = "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String LIBRARY = "xboxkrnl.exe";
    // name, direct branch references, distinct calling XAM function labels
    private static final String USAGE =
        "RtlLeaveCriticalSection\t1296\t1144\n" +
        "RtlEnterCriticalSection\t1240\t1113\n" +
        "KeLeaveCriticalRegion\t496\t432\n" +
        "KeEnterCriticalRegion\t460\t411\n" +
        "_snprintf\t334\t210\n" +
        "RtlInitAnsiString\t204\t168\n" +
        "NtClose\t201\t173\n" +
        "RtlInitializeCriticalSection\t167\t136\n" +
        "ExGetXConfigSetting\t157\t98\n" +
        "KeGetCurrentProcessType\t149\t129\n" +
        "RtlNtStatusToDosError\t139\t126\n" +
        "ObDereferenceObject\t126\t115\n" +
        "KeSetEvent\t125\t98\n" +
        "KfLowerIrql\t116\t59\n" +
        "KeReleaseSpinLockFromRaisedIrql\t112\t57\n" +
        "KfReleaseSpinLock\t99\t81\n" +
        "KfAcquireSpinLock\t98\t81\n" +
        "_snwprintf\t97\t54\n" +
        "KeQuerySystemTime\t95\t87\n" +
        "KeRaiseIrqlToDpcLevel\t90\t56\n" +
        "EtxProducerLog\t89\t89\n" +
        "KeAcquireSpinLockAtRaisedIrql\t89\t56\n" +
        "ExFreePool\t87\t55\n" +
        "KeWaitForSingleObject\t83\t74\n" +
        "XexCheckExecutablePrivilege\t67\t52\n" +
        "XeCryptRandom\t66\t51\n" +
        "ExReleaseReadWriteLock\t64\t56\n" +
        "XeCryptShaUpdate\t64\t28\n" +
        "NtSetInformationFile\t61\t46\n" +
        "NtOpenFile\t57\t56\n" +
        "XeCryptSha\t57\t47\n" +
        "XeCryptMd5Update\t57\t14\n" +
        "NtCreateFile\t53\t51\n" +
        "NtReadFile\t51\t36\n" +
        "ExSetXConfigSetting\t48\t35\n" +
        "NtWriteFile\t43\t27\n" +
        "XeCryptBnQw_SwapDwQwLeBe\t40\t16\n" +
        "EtxProducerRegister\t36\t31\n" +
        "sprintf\t36\t20\n" +
        "ExAllocatePoolTypeWithTag\t32\t27\n" +
        "XeCryptShaInit\t32\t27\n" +
        "XeKeysGetConsoleID\t30\t30\n" +
        "ExAcquireReadWriteLockShared\t29\t28\n" +
        "McaDeviceRequest\t28\t27\n" +
        "EtxProducerUnregister\t28\t25\n" +
        "KeTlsGetValue\t27\t20\n" +
        "NtQueryInformationFile\t25\t21\n" +
        "XeCryptShaFinal\t25\t21\n" +
        "ObReferenceObjectByHandle\t24\t24\n" +
        "ExAcquireReadWriteLockExclusive\t23\t23\n" +
        "NtCreateEvent\t23\t23\n" +
        "NtDeviceIoControlFile\t23\t16\n" +
        "KeReleaseSemaphore\t21\t19\n" +
        "RtlImageXexHeaderField\t21\t19\n" +
        "ExRegisterTitleTerminateNotification\t21\t15\n" +
        "IoSynchronousDeviceIoControlRequest\t20\t18\n" +
        "PsCamDeviceRequest\t20\t18\n" +
        "XeCryptHmacSha\t20\t12\n" +
        "XeKeysUnObfuscate\t19\t18\n" +
        "HalSendSMCMessage\t19\t14\n" +
        "XeCryptMd5Init\t19\t14\n" +
        "ObReferenceObjectByName\t18\t18\n" +
        "XexUnloadImage\t18\t17\n" +
        "XeKeysHmacSha\t17\t15\n" +
        "DbgPrint\t17\t7\n" +
        "DetroitDeviceRequest\t16\t16\n" +
        "NtWaitForSingleObjectEx\t16\t16\n" +
        "IoDismountVolumeByName\t16\t14\n" +
        "NicGetLinkState\t16\t13\n" +
        "RtlInitUnicodeString\t16\t13\n" +
        "NtAllocateVirtualMemory\t16\t10\n" +
        "KeResetEvent\t15\t12\n" +
        "NicGetOpt\t15\t12\n" +
        "NtFreeVirtualMemory\t14\t13\n" +
        "XexLoadImage\t14\t13\n" +
        "MmFreePhysicalMemory\t14\t11\n" +
        "StfsControlDevice\t14\t5\n" +
        "NtDeleteFile\t13\t13\n" +
        "RtlUnicodeToMultiByteN\t13\t11\n" +
        "ObTranslateSymbolicLink\t13\t10\n" +
        "XeCryptHmacShaVerify\t13\t10\n" +
        "XexGetProcedureAddress\t13\t9\n" +
        "ExInitializeReadWriteLock\t12\t11\n" +
        "KeSetPriorityClassThread\t12\t9\n" +
        "RtlCompareMemoryUlong\t12\t6\n" +
        "UsbdGetNatalHardwareVersion\t12\t6\n" +
        "KeInsertQueueDpc\t11\t11\n" +
        "XeKeysGetKey\t11\t11\n" +
        "KeTlsSetValue\t11\t6\n" +
        "ExCreateThread\t10\t10\n" +
        "KeBugCheckEx\t10\t10\n" +
        "KeQueryInterruptTime\t10\t10\n" +
        "ObReferenceObject\t10\t10\n" +
        "RtlCompareMemory\t10\t10\n" +
        "NtQueryFullAttributesFile\t10\t9\n" +
        "XeCryptAesCreateKeySchedule\t10\t9\n" +
        "VdQueryVideoMode\t10\t8\n" +
        "XeCryptMd5Final\t10\t8\n" +
        "XeKeysVerifyRSASignature\t10\t8\n" +
        "XeCryptHmacMd5\t10\t4\n" +
        "XeCryptSha256Update\t10\t3\n" +
        "XeCryptSha384Update\t10\t3\n" +
        "XeCryptSha512Update\t10\t3\n" +
        "NtQueryVolumeInformationFile\t9\t9\n" +
        "NtFlushBuffersFile\t9\t8\n" +
        "ExExpansionCall\t9\t7\n" +
        "MmPersistPhysicalMemoryAllocation\t9\t7\n" +
        "XeKeysConsolePrivateKeySign\t9\t7\n" +
        "_swprintf\t9\t6\n" +
        "KeSetBasePriorityThread\t9\t6\n" +
        "KeQueryPerformanceFrequency\t8\t8\n" +
        "XeCryptRc4\t8\t8\n" +
        "KeWaitForMultipleObjects\t8\t6\n" +
        "RtlTimeFieldsToTime\t8\t5\n" +
        "XexRegisterPatchDescriptor\t8\t5\n" +
        "XeCryptAesGcmUpdate\t8\t2\n" +
        "NtQueryDirectoryFile\t7\t7\n" +
        "XeCryptBnQwNeRsaPubCrypt\t7\t7\n" +
        "XeKeysObfuscate\t7\t7\n" +
        "RtlTimeToTimeFields\t7\t6\n" +
        "XeCryptAesCbcEncrypt\t7\t6\n" +
        "XeKeysConsoleSignatureVerification\t7\t6\n" +
        "ExReadModifyWriteXConfigSettingUlong\t7\t5\n" +
        "MmGetPhysicalAddress\t7\t5\n" +
        "NtSetEvent\t7\t5\n" +
        "XeCryptRc4Ecb\t7\t5\n" +
        "DumpRegisterDedicatedDataBlock\t7\t3\n" +
        "_vsnprintf\t6\t6\n" +
        "RtlMultiByteToUnicodeN\t6\t6\n" +
        "VdGetCurrentDisplayInformation\t6\t6\n" +
        "XeCryptBnDwLeDhModExp\t6\t6\n" +
        "DrvSetSysReqCallback\t6\t5\n" +
        "KeBugCheck\t6\t5\n" +
        "MmAllocatePhysicalMemoryEx\t6\t5\n" +
        "ObCreateSymbolicLink\t6\t5\n" +
        "RtlCompareStringN\t6\t5\n" +
        "XeCryptHmacShaUpdate\t6\t5\n" +
        "XeKeysSetProtectedFlag\t6\t4\n" +
        "XVoicedSendVPort\t6\t4\n" +
        "NicGetStats\t6\t3\n" +
        "XeCryptDesKey\t6\t3\n" +
        "XeCryptSha256Init\t6\t3\n" +
        "XeCryptSha384Init\t6\t3\n" +
        "XeCryptSha512Init\t6\t3\n" +
        "_vsnwprintf\t5\t5\n" +
        "KeInitializeDpc\t5\t5\n" +
        "KeInitializeTimerEx\t5\t5\n" +
        "NtClearEvent\t5\t5\n" +
        "RtlRaiseException\t5\t5\n" +
        "RtlTryEnterCriticalSection\t5\t5\n" +
        "XeCryptAesCbcDecrypt\t5\t5\n" +
        "XeCryptHmacShaFinal\t5\t5\n" +
        "XeKeysSecurityGetDetected\t5\t5\n" +
        "XexLoadImageHeaders\t5\t5\n" +
        "XInputdRawState\t5\t5\n" +
        "HalReturnToFirmware\t5\t4\n" +
        "IoDismountVolume\t5\t4\n" +
        "KeSetAffinityThread\t5\t4\n" +
        "XeCryptAesKey\t5\t4\n" +
        "XeCryptDes3Cbc\t5\t4\n" +
        "XeCryptDes3Key\t5\t4\n" +
        "DbgBreakPoint\t5\t3\n" +
        "KeInitializeSemaphore\t5\t3\n" +
        "XeKeysExSetKey\t5\t3\n" +
        "KeCancelTimer\t4\t4\n" +
        "KeSetTimerEx\t4\t4\n" +
        "NtDuplicateObject\t4\t4\n" +
        "NtYieldExecution\t4\t4\n" +
        "ObCreateObject\t4\t4\n" +
        "ObDeleteSymbolicLink\t4\t4\n" +
        "ObInsertObject\t4\t4\n" +
        "RtlUnicodeToUtf8\t4\t4\n" +
        "RtlUnicodeToUtf8Size\t4\t4\n" +
        "XeKeysGetStatus\t4\t4\n" +
        "XeKeysSecurityGetActivated\t4\t4\n" +
        "XexGetModuleHandle\t4\t4\n" +
        "XexGetModuleSection\t4\t4\n" +
        "XexLoadImageFromMemory\t4\t4\n" +
        "DevAuthGetStatistics\t4\t3\n" +
        "EtxConsumerDisableEventType\t4\t3\n" +
        "ExAllocatePoolWithTag\t4\t3\n" +
        "KeResumeThread\t4\t3\n" +
        "KeTlsAlloc\t4\t3\n" +
        "RtlCopyString\t4\t3\n" +
        "vsprintf\t4\t3\n" +
        "XeCryptBnQw_Copy\t4\t3\n" +
        "XeCryptDesParity\t4\t3\n" +
        "XeCryptHmacShaInit\t4\t3\n" +
        "XeCryptRc4Key\t4\t3\n" +
        "XInputdSetMinMaxAuthDelay\t4\t3\n" +
        "_vswprintf\t3\t3\n" +
        "ExAllocatePool\t3\t3\n" +
        "ExTerminateThread\t3\t3\n" +
        "ExTryToAcquireReadWriteLockShared\t3\t3\n" +
        "HalPowerDownToBackgroundMode\t3\t3\n" +
        "IoCompleteRequest\t3\t3\n" +
        "IoDeleteDevice\t3\t3\n" +
        "KeDelayExecutionThread\t3\t3\n" +
        "LDIDestroyDecompression\t3\t3\n" +
        "MtpdGetCurrentDevices\t3\t3\n" +
        "NicSetOpt\t3\t3\n" +
        "NtProtectVirtualMemory\t3\t3\n" +
        "NtSetSystemTime\t3\t3\n" +
        "ObOpenObjectByName\t3\t3\n" +
        "SataCdRomRecordReset\t3\t3\n" +
        "StfsCreateDevice\t3\t3\n" +
        "TidDeviceRequest\t3\t3\n" +
        "VdCallGraphicsNotificationRoutines\t3\t3\n" +
        "VdGetDisplayDiscoveryData\t3\t3\n" +
        "XeCryptBnQwBeSigVerify\t3\t3\n" +
        "XeCryptRotSumSha\t3\t3\n" +
        "XeKeysExSaveKeyVault\t3\t3\n" +
        "XeKeysGetMediaID\t3\t3\n" +
        "XeKeysQwNeRsaPrvCrypt\t3\t3\n" +
        "XInputdFFDeviceControl\t3\t3\n" +
        "HalRegisterSMCNotification\t3\t2\n" +
        "MmQueryAddressProtect\t3\t2\n" +
        "VdSetDisplayModeOverride\t3\t2\n" +
        "VdSetSystemCommandBufferGpuIdentifierAddress\t3\t2\n" +
        "XAudioSetSpeakerConfig\t3\t2\n" +
        "XeCryptAesEcb\t3\t2\n" +
        "XVoicedClose\t3\t2\n" +
        "XeKeysExGetKey\t3\t1\n" +
        "XexLoadExecutable\t3\t1\n" +
        "_vscwprintf\t2\t2\n" +
        "AniBlockOnAnimation\t2\t2\n" +
        "AniTerminateAnimation\t2\t2\n" +
        "EtxConsumerEnableEventType\t2\t2\n" +
        "ExTerminateTitleProcess\t2\t2\n" +
        "HalNotifyAddRemoveBackgroundTask\t2\t2\n" +
        "HalRegisterXamPowerDownCallback\t2\t2\n" +
        "HidReadKeys\t2\t2\n" +
        "IoDismountVolumeByFileHandle\t2\t2\n" +
        "KeCallAndWaitForDpcRoutine\t2\t2\n" +
        "KeRemoveQueueDpc\t2\t2\n" +
        "KeSetTimer\t2\t2\n" +
        "KeTlsFree\t2\t2\n" +
        "LDICreateDecompression\t2\t2\n" +
        "LDIDecompress\t2\t2\n" +
        "MmAllocatePhysicalMemory\t2\t2\n" +
        "MmQueryAllocationSize\t2\t2\n" +
        "MmUnmapMemory\t2\t2\n" +
        "MtpdReadData\t2\t2\n" +
        "NtCreateDirectoryObject\t2\t2\n" +
        "NtQueueApcThread\t2\t2\n" +
        "NtResumeThread\t2\t2\n" +
        "ObOpenObjectByPointer\t2\t2\n" +
        "RtlAppendStringToString\t2\t2\n" +
        "RtlFillMemoryUlong\t2\t2\n" +
        "RtlUnicodeStringToAnsiString\t2\t2\n" +
        "UsbdGetNatalHub\t2\t2\n" +
        "VdDisplayFatalError\t2\t2\n" +
        "VdQueryRealVideoMode\t2\t2\n" +
        "VdSet3dVideoFormat\t2\t2\n" +
        "VdSetDisplayMode\t2\t2\n" +
        "VdSetGraphicsInterruptCallback\t2\t2\n" +
        "VdShutdownEngines\t2\t2\n" +
        "XAudioSetVoiceCategoryVolume\t2\t2\n" +
        "XAudioUnregisterRenderDriverClient\t2\t2\n" +
        "XeCryptAesCbc\t2\t2\n" +
        "XeCryptAesGcmFinalize\t2\t2\n" +
        "XeCryptAesGcmInitialize\t2\t2\n" +
        "XeCryptBnDwLeDhInvalBase\t2\t2\n" +
        "XeCryptMd5\t2\t2\n" +
        "XeKeysGetKeyProperties\t2\t2\n" +
        "XeKeysGetProtectedFlag\t2\t2\n" +
        "XeKeysSecuritySetActivated\t2\t2\n" +
        "XeKeysSecuritySetDetected\t2\t2\n" +
        "XexSetLastKdcTime\t2\t2\n" +
        "XexVerifyImageHeaders\t2\t2\n" +
        "XInputdGetDeviceStats\t2\t2\n" +
        "XInputdGetFailedConnectionOrBind\t2\t2\n" +
        "XInputdNotify\t2\t2\n" +
        "XInputdReadState\t2\t2\n" +
        "XVoicedActivate\t2\t2\n" +
        "DrvGetContentStorageNotification\t2\t1\n" +
        "ExTryToAcquireReadWriteLockExclusive\t2\t1\n" +
        "HalClampUnclampOutputDACs\t2\t1\n" +
        "KeSetCurrentProcessType\t2\t1\n" +
        "NicUpdateMcastMembership\t2\t1\n" +
        "NtQueryVirtualMemory\t2\t1\n" +
        "RtlComputeCrc32\t2\t1\n" +
        "VdRetrainEDRAM\t2\t1\n" +
        "XeCryptBnQwNeCompare\t2\t1\n" +
        "XInputdSetTextDeviceKeyLocks\t2\t1\n" +
        "AniSetLogo\t1\t1\n" +
        "AniStartBootAnimation\t1\t1\n" +
        "DrvSetAudioLatencyCallback\t1\t1\n" +
        "DrvSetContentStorageCallback\t1\t1\n" +
        "DrvSetDeviceConfigChangeCallback\t1\t1\n" +
        "DrvSetMicArrayStartCallback\t1\t1\n" +
        "DrvSetUserBindingCallback\t1\t1\n" +
        "DumpGetRawDumpInfo\t1\t1\n" +
        "DumpUpdateDumpSettings\t1\t1\n" +
        "EtxConsumerFlushBuffers\t1\t1\n" +
        "EtxConsumerProcessLogs\t1\t1\n" +
        "EtxConsumerRegister\t1\t1\n" +
        "EtxConsumerUnregister\t1\t1\n" +
        "HalCallBackgroundModeNotificationRoutines\t1\t1\n" +
        "HalFinalizePowerLossRecovery\t1\t1\n" +
        "HalGetCurrentAVPack\t1\t1\n" +
        "HalGetNotedArgonErrors\t1\t1\n" +
        "HalGetPowerUpCause\t1\t1\n" +
        "HalNotifyBackgroundModeTransitionComplete\t1\t1\n" +
        "HalReadArgonEeprom\t1\t1\n" +
        "HalRegisterBackgroundModeTransitionCallback\t1\t1\n" +
        "HalRegisterHdDvdRomNotification\t1\t1\n" +
        "HidGetCapabilities\t1\t1\n" +
        "HidGetLastInputTime\t1\t1\n" +
        "IoBuildSynchronousFsdRequest\t1\t1\n" +
        "IoCallDriver\t1\t1\n" +
        "IoCreateDevice\t1\t1\n" +
        "KeInitializeApc\t1\t1\n" +
        "KeInsertQueueApc\t1\t1\n" +
        "KeLockL2\t1\t1\n" +
        "KePulseEvent\t1\t1\n" +
        "KeQueryBasePriorityThread\t1\t1\n" +
        "KeSetCurrentStackPointers\t1\t1\n" +
        "KeSetPowerMode\t1\t1\n" +
        "KeSetPriorityThread\t1\t1\n" +
        "KeSuspendThread\t1\t1\n" +
        "KeTryToAcquireSpinLockAtRaisedIrql\t1\t1\n" +
        "KeUnlockL2\t1\t1\n" +
        "KfRaiseIrql\t1\t1\n" +
        "KiApcNormalRoutineNop\t1\t1\n" +
        "LDIResetDecompression\t1\t1\n" +
        "MmDoubleMapMemory\t1\t1\n" +
        "MmGetPoolPagesType\t1\t1\n" +
        "MmResetLowestAvailablePages\t1\t1\n" +
        "MtpdBeginTransaction\t1\t1\n" +
        "MtpdCancelTransaction\t1\t1\n" +
        "MtpdEndTransaction\t1\t1\n" +
        "MtpdResetDevice\t1\t1\n" +
        "MtpdSendData\t1\t1\n" +
        "MtpdVerifyProximity\t1\t1\n" +
        "NicAttach\t1\t1\n" +
        "NicDetach\t1\t1\n" +
        "NicFlushXmitQueue\t1\t1\n" +
        "NicSetUnicastAddress\t1\t1\n" +
        "NicXmit\t1\t1\n" +
        "NomnilGetExtension\t1\t1\n" +
        "NomnilSetLed\t1\t1\n" +
        "NtAllocateEncryptedMemory\t1\t1\n" +
        "NtCancelIoFileEx\t1\t1\n" +
        "NtCancelTimer\t1\t1\n" +
        "NtCreateMutant\t1\t1\n" +
        "NtCreateTimer\t1\t1\n" +
        "NtOpenSymbolicLinkObject\t1\t1\n" +
        "NtQuerySymbolicLinkObject\t1\t1\n" +
        "NtReleaseMutant\t1\t1\n" +
        "NtSetTimerEx\t1\t1\n" +
        "NtWaitForMultipleObjectsEx\t1\t1\n" +
        "ObGetWaitableObject\t1\t1\n" +
        "RtlCaptureContext\t1\t1\n" +
        "RtlCopyUnicodeString\t1\t1\n" +
        "RtlFreeAnsiString\t1\t1\n" +
        "RtlInitializeCriticalSectionAndSpinCount\t1\t1\n" +
        "RtlUnwind\t1\t1\n" +
        "SvodCreateDevice\t1\t1\n" +
        "UsbdGetRequiredDrivers\t1\t1\n" +
        "UsbdNatalHubRegisterNotificationCallback\t1\t1\n" +
        "UsbdResetDevice\t1\t1\n" +
        "VdEnableDisableClockGating\t1\t1\n" +
        "VdEnableRingBufferRPtrWriteBack\t1\t1\n" +
        "VdGet3dVideoFormat\t1\t1\n" +
        "VdGetCurrentDisplayGamma\t1\t1\n" +
        "VdGetSystemCommandBuffer\t1\t1\n" +
        "VdInitializeEngines\t1\t1\n" +
        "VdInitializeRingBuffer\t1\t1\n" +
        "VdInitializeScalerCommandBuffer\t1\t1\n" +
        "VdIsHSIOTrainingSucceeded\t1\t1\n" +
        "VdPersistDisplay\t1\t1\n" +
        "VdQuerySystemCommandBuffer\t1\t1\n" +
        "VdQueryVideoFlags\t1\t1\n" +
        "VdRegisterXamGraphicsNotification\t1\t1\n" +
        "VdRetrainEDRAMWorker\t1\t1\n" +
        "VdSetSystemCommandBuffer\t1\t1\n" +
        "VdSwap\t1\t1\n" +
        "XAudioCaptureRenderDriverFrame\t1\t1\n" +
        "XAudioEnableDucker\t1\t1\n" +
        "XAudioGetDuckerAttackTime\t1\t1\n" +
        "XAudioGetDuckerHoldTime\t1\t1\n" +
        "XAudioGetDuckerLevel\t1\t1\n" +
        "XAudioGetDuckerReleaseTime\t1\t1\n" +
        "XAudioGetDuckerThreshold\t1\t1\n" +
        "XAudioGetRenderDriverTic\t1\t1\n" +
        "XAudioGetSpeakerConfig\t1\t1\n" +
        "XAudioGetVoiceCategoryVolume\t1\t1\n" +
        "XAudioGetVoiceCategoryVolumeChangeMask\t1\t1\n" +
        "XAudioRegisterRenderDriverClient\t1\t1\n" +
        "XAudioRegisterRenderDriverMECClient\t1\t1\n" +
        "XAudioSetDuckerLevel\t1\t1\n" +
        "XAudioSubmitRenderDriverFrame\t1\t1\n" +
        "XAudioUnregisterRenderDriverMECClient\t1\t1\n" +
        "XeCryptBnDwLeDhEqualBase\t1\t1\n" +
        "XeCryptBnDwLePkcs1Verify\t1\t1\n" +
        "XeCryptBnQwNeRsaPrvCrypt\t1\t1\n" +
        "XeCryptChainAndSumMac\t1\t1\n" +
        "XeCryptDesCbc\t1\t1\n" +
        "XeCryptDesEcb\t1\t1\n" +
        "XeCryptSha256Final\t1\t1\n" +
        "XeCryptSha384Final\t1\t1\n" +
        "XeCryptSha512Final\t1\t1\n" +
        "XeKeysAesCbc\t1\t1\n" +
        "XeKeysExecute\t1\t1\n" +
        "XeKeysGetConsoleCertificate\t1\t1\n" +
        "XeKeysRevokeIsDeviceRevoked\t1\t1\n" +
        "XeKeysSecuritySetStat\t1\t1\n" +
        "XeKeysSetKey\t1\t1\n" +
        "XeKeysSetRevocationList\t1\t1\n" +
        "XexActivationGetNonce\t1\t1\n" +
        "XexActivationSetLicense\t1\t1\n" +
        "XexActivationVerifyOwnership\t1\t1\n" +
        "XexSendDeferredNotifications\t1\t1\n" +
        "XexShimEnable\t1\t1\n" +
        "XexShimEntryEnable\t1\t1\n" +
        "XexShimLock\t1\t1\n" +
        "XexStartExecutable\t1\t1\n" +
        "XexUnloadTitleModules\t1\t1\n" +
        "XInputdControl\t1\t1\n" +
        "XInputdFFSetDeviceGain\t1\t1\n" +
        "XInputdFFSetRumble\t1\t1\n" +
        "XInputdGetCapabilities\t1\t1\n" +
        "XInputdGetDevicePid\t1\t1\n" +
        "XInputdGetLastTextInputTime\t1\t1\n" +
        "XInputdGetTextDeviceKeyLocks\t1\t1\n" +
        "XInputdPowerDownDevice\t1\t1\n" +
        "XInputdReadTextKeystroke\t1\t1\n" +
        "XInputdSendStayAliveRequest\t1\t1\n" +
        "XInputdSetFailedConnectionOrBindCallback\t1\t1\n" +
        "XInputdSetRingOfLight\t1\t1\n" +
        "XInputdWriteState\t1\t1\n" +
        "XMACreateContext\t1\t1\n" +
        "XMAReleaseContext\t1\t1\n" +
        "XVoicedGetBatteryStatus\t1\t1\n" +
        "XVoicedGetDirectionalData\t1\t1\n" +
        "XVoicedHeadsetPresent\t1\t1\n" +
        "XVoicedSubmitPacket\t1\t1\n" +
        "__C_specific_handler\t0\t0\n" +
        "DrvSetAutobind\t0\t0\n" +
        "IoInvalidDeviceRequest\t0\t0\n" +
        "VdQueryVideoCapabilities\t0\t0\n" +
        "XVoicedIsActiveProcess\t0\t0\n";

    private static class Weight {
        final int refs, callers;
        Weight(int refs, int callers) { this.refs = refs; this.callers = callers; }
    }
    private static class Row {
        String name, status="", kernelAddress="", kernelSignature="", source="",
            ret="", extSignature="", notes="", externalSpace="";
        int refs, callers, nparams, nopaque;
    }
    private Map<String,Weight> readWeights() {
        Map<String,Weight> m=new HashMap<>();
        for (String line: USAGE.split("\n")) {
            String[] p=line.split("\t",-1);
            if (p.length != 3 || m.put(p[0],new Weight(Integer.parseInt(p[1]),Integer.parseInt(p[2])))!=null)
                throw new IllegalStateException("Malformed/duplicate usage row "+line);
        }
        if (m.size()!=443) throw new IllegalStateException("Ranked import list must be 443 names");
        return m;
    }
    private Function exactKernelFunction(Program k, ExternalLocation loc, Row r) {
        Address address=loc.getAddress();
        if (address!=null && address.isMemoryAddress()) {
            Function f=k.getFunctionManager().getFunctionAt(address);
            if (f!=null) {
                if (f.getName().equals(r.name)) { r.notes="exact linked address and name";return f; }
                r.status="LINKED_ADDRESS_CONFLICT";
                r.notes="linked address points to "+f.getName()+"@"+f.getEntryPoint();
                return null;
            }
        }
        Function best=null;
        SymbolIterator it=k.getSymbolTable().getSymbols(r.name);
        while (it.hasNext()) {
            Symbol s=it.next();
            if (!s.getAddress().isMemoryAddress()) continue;
            Function f=k.getFunctionManager().getFunctionAt(s.getAddress());
            if (f==null || !f.getName().equals(r.name)) continue;
            if (best!=null && !best.getEntryPoint().equals(f.getEntryPoint())) {
                r.status="AMBIGUOUS_KERNEL_NAME";
                r.notes="more than one function with this exact name";
                return null;
            }
            best=f;
        }
        r.notes=best==null?"no matching kernel function entry":
            "unique kernel function name; imported external address absent/unresolved";
        return best;
    }
    private Row evaluate(Program kernel, ExternalLocation loc, Map<String,Weight> weight) {
        Row r=new Row();
        r.name=loc.getLabel();
        Weight w=weight.get(r.name);
        if (w!=null) {r.refs=w.refs;r.callers=w.callers;}
        r.externalSpace=String.valueOf(loc.getExternalSpaceAddress());
        Function imported=loc.getFunction();
        if (imported!=null) r.extSignature=imported.getPrototypeString(true,false);
        Function f=exactKernelFunction(kernel,loc,r);
        if (f==null) {
            if (r.status.length()==0) r.status="KERNEL_ENTRY_UNRESOLVED";
            return r;
        }
        r.kernelAddress=String.valueOf(f.getEntryPoint());
        r.kernelSignature=f.getPrototypeString(true,false);
        r.source=String.valueOf(f.getSignatureSource());
        r.ret=f.getReturnType().getDisplayName();
        r.nparams=f.getParameterCount();
        for (Parameter p:f.getParameters()) {
            String type=p.getDataType().getName();
            if (type.startsWith("undefined") || "pointer".equals(type)) r.nopaque++;
        }
        boolean returnOpaque=f.getReturnType().getName().startsWith("undefined");
        if (imported!=null && imported.getParameterCount()!=r.nparams)
            r.notes += "; XAM external params="+imported.getParameterCount()+" kernel params="+r.nparams;
        if (f.hasCustomVariableStorage()) r.notes += "; custom storage retained";
        if (returnOpaque || r.nopaque>0) r.status="OPAQUE_TYPES";
        else if (r.nparams==0 && r.refs>0 && !"USER_DEFINED".equals(r.source))
            r.status="REVIEW_ZERO_PARAMETER_SIGNATURE";
        else if (!"USER_DEFINED".equals(r.source))
            r.status="TYPED_NON_USER_DEFINED";
        else r.status="TYPED_USER_DEFINED";
        return r;
    }
    private String t(String v) {
        return v==null?"":v.replace('\t',' ').replace('\n',' ').replace('\r',' ');
    }
    private void emit(PrintWriter p, Row r) {
        p.println(t(r.name)+"\t"+r.refs+"\t"+r.callers+"\t"+t(r.status)+"\t"+
            t(r.kernelAddress)+"\t"+t(r.kernelSignature)+"\t"+t(r.source)+"\t"+
            t(r.ret)+"\t"+r.nparams+"\t"+r.nopaque+"\t"+t(r.externalSpace)+
            "\t"+t(r.extSignature)+"\t"+t(r.notes));
    }
    @Override protected void run() throws Exception {
        if (!"xam.xex".equalsIgnoreCase(currentProgram.getName()) ||
            !XAM_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("Wrong XAM program SHA or language");
        ExternalManager em=currentProgram.getExternalManager();
        String path=em.getExternalLibraryPath(LIBRARY);
        if (path==null || path.length()==0)
            throw new IllegalStateException("Link xboxkrnl.exe in this Ghidra project first");
        DomainFile file=state.getProject().getProjectData().getFile(path);
        if (file==null) throw new IllegalStateException("Linked kernel missing: "+path);
        Program kernel=null;
        try {
            kernel=(Program)file.getReadOnlyDomainObject(this,-1,monitor);
            if (!KERNEL_SHA.equalsIgnoreCase(kernel.getExecutableSHA256()) ||
                !LANGUAGE.equals(kernel.getLanguageID().getIdAsString()))
                throw new IllegalStateException("Linked kernel SHA/language mismatch: "+
                    kernel.getExecutableSHA256());
            Map<String,Weight> w=readWeights();
            Map<String,Row> result=new HashMap<>();
            int dup=0, unranked=0, data=0;
            ExternalLocationIterator it=em.getExternalLocations(LIBRARY);
            while (it.hasNext()) {
                monitor.checkCancelled();
                ExternalLocation loc=it.next();
                if (!loc.isFunction()) { data++;continue; }
                Row r=evaluate(kernel,loc,w);
                if (result.putIfAbsent(r.name,r)!=null) dup++;
                if (!w.containsKey(r.name)) unranked++;
            }
            List<Row> ordered=new ArrayList<>(result.values());
            ordered.sort((a,b)-> {
                int n=Integer.compare(b.refs,a.refs);
                return n==0?a.name.compareTo(b.name):n;
            });
            File downloads=new File(System.getProperty("user.home"),"Downloads");
            File directory=downloads.isDirectory()?downloads:
                new File(System.getProperty("java.io.tmpdir"));
            File report=File.createTempFile("Xam17559KernelContractAudit_",".tsv",directory);
            Map<String,Integer> statuses=new TreeMap<>();
            try (PrintWriter p=new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(report),StandardCharsets.UTF_8))) {
                p.println("kernel_import\tbranch_refs\tdistinct_xam_caller_labels\tcontract_bucket"+
                    "\tkernel_address\tkernel_signature\tsignature_source\treturn_type"+
                    "\tkernel_parameter_count\topaque_parameter_count\texternal_space_address"+
                    "\txam_external_signature\tnotes");
                for (Row r:ordered) {
                    emit(p,r);
                    statuses.put(r.status,statuses.getOrDefault(r.status,0)+1);
                }
            }
            println("XAM17559_KERNEL_CONTRACTS READ_ONLY XAM="+currentProgram.getExecutableSHA256()+
                " KERNEL="+kernel.getExecutableSHA256()+" LINK="+path);
            println("IMPORT_COUNT="+result.size()+" ranked="+w.size()+" duplicated="+dup+
                " unranked="+unranked+" dataExternals="+data);
            println("BUCKET_COUNTS "+statuses);
            for (int i=0;i<Math.min(45,ordered.size());i++) {
                Row r=ordered.get(i);
                println("RANK "+(i+1)+" "+r.name+" branches="+r.refs+" callers="+r.callers+
                    " kernel="+r.kernelAddress+" bucket="+r.status+" source="+r.source);
            }
            println("REPORT "+report.getAbsolutePath());
            println("DONE XAM and kernel databases unchanged");
        } finally {
            if (kernel!=null) kernel.release(this);
        }
    }
}
