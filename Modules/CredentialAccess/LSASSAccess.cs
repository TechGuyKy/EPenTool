using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.CredentialAccess
{
    public class LSASSAccess
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<LSASSAccess> _logger;
        private readonly SecurityContext _securityContext;

        public LSASSAccess(IConfiguration configuration, ILogger<LSASSAccess> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<LSASSAccessResult>> ExecuteAsync()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                _logger.LogInformation("Starting LSASS memory access assessment");

                results.AddRange(await CheckLSASSProcess());
                results.AddRange(await CheckMemoryDumping());
                results.AddRange(await CheckProcessAccess());
                results.AddRange(await CheckMimikatzDetection());
                results.AddRange(await CheckLSAProtections());
                results.AddRange(await CheckCredentialGuard());
                results.AddRange(await CheckWDigestSettings());

                _logger.LogInformation($"LSASS access assessment completed. Found {results.Count} techniques");
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LSASS access execution failed");
                results.Add(new LSASSAccessResult
                {
                    TechniqueName = "LSASS Access Error",
                    Success = false,
                    Severity = "Error",
                    Description = "LSASS access assessment failed",
                    Evidence = ex.Message
                });
                return results;
            }
        }

        private async Task<List<LSASSAccessResult>> CheckLSASSProcess()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                await Task.Run(() =>
                {
                    var lsassProcesses = Process.GetProcessesByName("lsass");

                    if (lsassProcesses.Length > 0)
                    {
                        foreach (var lsassProcess in lsassProcesses)
                        {
                            try
                            {
                                results.Add(new LSASSAccessResult
                                {
                                    TechniqueName = "LSASS Process Detection",
                                    Success = true,
                                    Severity = "Info",
                                    Description = $"LSASS process found: PID {lsassProcess.Id}",
                                    Evidence = $"Process: lsass.exe, PID: {lsassProcess.Id}, Session: {lsassProcess.SessionId}",
                                    ProcessId = lsassProcess.Id,
                                    ProcessName = lsassProcess.ProcessName,
                                    AccessMethod = "Process Enumeration"
                                });

                                CheckLSASSProcessDetails(lsassProcess, results);
                            }
                            finally
                            {
                                lsassProcess?.Dispose();
                            }
                        }
                    }
                    else
                    {
                        results.Add(new LSASSAccessResult
                        {
                            TechniqueName = "LSASS Process Detection",
                            Success = false,
                            Severity = "Error",
                            Description = "LSASS process not found",
                            Evidence = "No lsass.exe process detected",
                            AccessMethod = "Process Enumeration"
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check LSASS process");
            }

            return results;
        }

        private async Task<List<LSASSAccessResult>> CheckMemoryDumping()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (_securityContext.IsElevated)
                    {
                        var dumpMethods = GetMemoryDumpMethods();

                        foreach (var method in dumpMethods)
                        {
                            var canDump = CanPerformMemoryDump(method);

                            results.Add(new LSASSAccessResult
                            {
                                TechniqueName = "LSASS Memory Dumping",
                                Success = canDump,
                                Severity = canDump ? "Critical" : "Low",
                                Description = $"LSASS memory dump method: {method.Name}",
                                Evidence = $"Method: {method.Name}, Tool: {method.Tool}, Accessible: {canDump}",
                                AccessMethod = method.Name,
                                DumpMethod = method.Tool,
                                RequiresElevation = method.RequiresElevation
                            });
                        }

                        CheckProcessDumpAccess(results);
                    }
                    else
                    {
                        results.Add(new LSASSAccessResult
                        {
                            TechniqueName = "Memory Dump Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Memory dumping assessment requires elevated privileges",
                            Evidence = "Current process lacks administrative privileges",
                            RequiresElevation = true
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check memory dumping");
            }

            return results;
        }

        private async Task<List<LSASSAccessResult>> CheckProcessAccess()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                await Task.Run(() =>
                {
                    var lsassProcesses = Process.GetProcessesByName("lsass");

                    foreach (var lsassProcess in lsassProcesses)
                    {
                        try
                        {
                            var accessRights = CheckProcessAccessRights(lsassProcess.Id);

                            foreach (var right in accessRights)
                            {
                                results.Add(new LSASSAccessResult
                                {
                                    TechniqueName = "LSASS Process Access Rights",
                                    Success = right.HasAccess,
                                    Severity = right.HasAccess ? "High" : "Low",
                                    Description = $"Process access right: {right.AccessType}",
                                    Evidence = $"Access: {right.AccessType}, Available: {right.HasAccess}",
                                    ProcessId = lsassProcess.Id,
                                    AccessMethod = "Direct Process Access",
                                    AccessRights = right.AccessType
                                });
                            }
                        }
                        finally
                        {
                            lsassProcess?.Dispose();
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check process access");
            }

            return results;
        }

        private async Task<List<LSASSAccessResult>> CheckMimikatzDetection()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                await Task.Run(() =>
                {
                    var mimikatzMethods = GetMimikatzMethods();

                    foreach (var method in mimikatzMethods)
                    {
                        results.Add(new LSASSAccessResult
                        {
                            TechniqueName = "Mimikatz Method Analysis",
                            Success = true,
                            Severity = "High",
                            Description = $"Mimikatz method available: {method.Name}",
                            Evidence = $"Method: {method.Name}, Target: {method.Target}",
                            AccessMethod = method.Name,
                            MimikatzMethod = method.Name,
                            TargetCredentials = method.Target
                        });
                    }

                    CheckMimikatzDetectors(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check Mimikatz detection");
            }

            return results;
        }

        private async Task<List<LSASSAccessResult>> CheckLSAProtections()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                await Task.Run(() =>
                {
                    var lsaProtections = CheckLSAProtectionStatus();

                    results.Add(new LSASSAccessResult
                    {
                        TechniqueName = "LSA Protection Status",
                        Success = true,
                        Severity = lsaProtections.IsProtected ? "Low" : "High",
                        Description = $"LSA Protection: {(lsaProtections.IsProtected ? "Enabled" : "Disabled")}",
                        Evidence = $"Protected: {lsaProtections.IsProtected}, Method: {lsaProtections.Method}",
                        LSAProtected = lsaProtections.IsProtected,
                        ProtectionLevel = lsaProtections.Level
                    });

                    if (!lsaProtections.IsProtected)
                    {
                        results.Add(new LSASSAccessResult
                        {
                            TechniqueName = "Unprotected LSASS Process",
                            Success = true,
                            Severity = "Critical",
                            Description = "LSASS process is not protected - direct memory access possible",
                            Evidence = "LSA Protection disabled, RunAsPPL not enabled",
                            LSAProtected = false
                        });
                    }

                    CheckPPLStatus(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check LSA protections");
            }

            return results;
        }

        private async Task<List<LSASSAccessResult>> CheckCredentialGuard()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                await Task.Run(() =>
                {
                    var credGuardStatus = GetCredentialGuardStatus();

                    results.Add(new LSASSAccessResult
                    {
                        TechniqueName = "Credential Guard Status",
                        Success = true,
                        Severity = credGuardStatus.IsEnabled ? "Low" : "High",
                        Description = $"Windows Defender Credential Guard: {(credGuardStatus.IsEnabled ? "Enabled" : "Disabled")}",
                        Evidence = $"Status: {credGuardStatus.Status}, Version: {credGuardStatus.Version}",
                        CredentialGuardEnabled = credGuardStatus.IsEnabled,
                        CredentialGuardStatus = credGuardStatus.Status
                    });

                    if (!credGuardStatus.IsEnabled)
                    {
                        results.Add(new LSASSAccessResult
                        {
                            TechniqueName = "Credential Guard Disabled",
                            Success = true,
                            Severity = "High",
                            Description = "Windows Defender Credential Guard is not enabled",
                            Evidence = "Credentials stored in LSASS memory are accessible",
                            CredentialGuardEnabled = false
                        });
                    }

                    CheckVBSStatus(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check Credential Guard");
            }

            return results;
        }

        private async Task<List<LSASSAccessResult>> CheckWDigestSettings()
        {
            var results = new List<LSASSAccessResult>();

            try
            {
                await Task.Run(() =>
                {
                    var wdigestSettings = GetWDigestSettings();

                    results.Add(new LSASSAccessResult
                    {
                        TechniqueName = "WDigest Authentication Settings",
                        Success = true,
                        Severity = wdigestSettings.PlaintextEnabled ? "Critical" : "Low",
                        Description = $"WDigest plaintext passwords: {(wdigestSettings.PlaintextEnabled ? "Enabled" : "Disabled")}",
                        Evidence = $"UseLogonCredential: {wdigestSettings.UseLogonCredential}, Negotiable: {wdigestSettings.Negotiable}",
                        WDigestEnabled = wdigestSettings.PlaintextEnabled
                    });

                    if (wdigestSettings.PlaintextEnabled)
                    {
                        results.Add(new LSASSAccessResult
                        {
                            TechniqueName = "WDigest Plaintext Storage",
                            Success = true,
                            Severity = "Critical",
                            Description = "WDigest is storing plaintext passwords in memory",
                            Evidence = "UseLogonCredential registry value enables plaintext storage",
                            WDigestEnabled = true,
                            CredentialsExtracted = 1
                        });
                    }

                    CheckSSPSettings(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check WDigest settings");
            }

            return results;
        }

        private void CheckLSASSProcessDetails(Process lsassProcess, List<LSASSAccessResult> results)
        {
            try
            {
                var processDetails = GetProcessDetails(lsassProcess);

                results.Add(new LSASSAccessResult
                {
                    TechniqueName = "LSASS Process Analysis",
                    Success = true,
                    Severity = "Info",
                    Description = "LSASS process details analyzed",
                    Evidence = $"Memory: {processDetails.WorkingSet / 1024 / 1024}MB, Threads: {processDetails.Threads}, Handles: {processDetails.Handles}",
                    ProcessId = lsassProcess.Id,
                    ProcessMemorySize = processDetails.WorkingSet,
                    ProcessThreads = processDetails.Threads
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get LSASS process details");
            }
        }

        private List<MemoryDumpMethod> GetMemoryDumpMethods()
        {
            return new List<MemoryDumpMethod>
            {
                new MemoryDumpMethod { Name = "Task Manager", Tool = "taskmgr.exe", RequiresElevation = true },
                new MemoryDumpMethod { Name = "ProcDump", Tool = "procdump.exe", RequiresElevation = true },
                new MemoryDumpMethod { Name = "Process Hacker", Tool = "ProcessHacker.exe", RequiresElevation = true },
                new MemoryDumpMethod { Name = "Comsvcs.dll", Tool = "rundll32.exe", RequiresElevation = true },
                new MemoryDumpMethod { Name = "PowerShell", Tool = "powershell.exe", RequiresElevation = true },
                new MemoryDumpMethod { Name = "WER", Tool = "WerFault.exe", RequiresElevation = false }
            };
        }

        private bool CanPerformMemoryDump(MemoryDumpMethod method)
        {
            try
            {
                if (method.RequiresElevation && !_securityContext.IsElevated)
                    return false;

                return method.Tool switch
                {
                    "taskmgr.exe" => File.Exists(Path.Combine(Environment.SystemDirectory, "taskmgr.exe")),
                    "rundll32.exe" => File.Exists(Path.Combine(Environment.SystemDirectory, "rundll32.exe")),
                    "powershell.exe" => File.Exists(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")),
                    "WerFault.exe" => File.Exists(Path.Combine(Environment.SystemDirectory, "WerFault.exe")),
                    _ => false
                };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check dump method: {method.Name}");
                return false;
            }
        }

        private void CheckProcessDumpAccess(List<LSASSAccessResult> results)
        {
            try
            {
                var lsassProcesses = Process.GetProcessesByName("lsass");
                foreach (var lsassProcess in lsassProcesses)
                {
                    try
                    {
                        var handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, lsassProcess.Id);
                        if (handle != IntPtr.Zero)
                        {
                            CloseHandle(handle);

                            results.Add(new LSASSAccessResult
                            {
                                TechniqueName = "Direct Memory Access",
                                Success = true,
                                Severity = "Critical",
                                Description = "Direct LSASS memory access is possible",
                                Evidence = $"Successfully opened LSASS process handle (PID: {lsassProcess.Id})",
                                ProcessId = lsassProcess.Id,
                                AccessMethod = "OpenProcess API"
                            });
                        }
                    }
                    finally
                    {
                        lsassProcess?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check process dump access");
            }
        }

        private List<ProcessAccessRight> CheckProcessAccessRights(int processId)
        {
            var accessRights = new List<ProcessAccessRight>();

            try
            {
                var rights = new[]
                {
                    new { Type = "PROCESS_QUERY_INFORMATION", Value = PROCESS_QUERY_INFORMATION },
                    new { Type = "PROCESS_VM_READ", Value = PROCESS_VM_READ },
                    new { Type = "PROCESS_VM_WRITE", Value = PROCESS_VM_WRITE },
                    new { Type = "PROCESS_CREATE_THREAD", Value = PROCESS_CREATE_THREAD }
                };

                foreach (var right in rights)
                {
                    try
                    {
                        var handle = OpenProcess(right.Value, false, processId);
                        var hasAccess = handle != IntPtr.Zero;

                        if (hasAccess)
                            CloseHandle(handle);

                        accessRights.Add(new ProcessAccessRight
                        {
                            AccessType = right.Type,
                            HasAccess = hasAccess
                        });
                    }
                    catch
                    {
                        accessRights.Add(new ProcessAccessRight
                        {
                            AccessType = right.Type,
                            HasAccess = false
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check process access rights for PID: {processId}");
            }

            return accessRights;
        }

        private List<MimikatzMethod> GetMimikatzMethods()
        {
            return new List<MimikatzMethod>
            {
                new MimikatzMethod { Name = "sekurlsa::logonpasswords", Target = "Plaintext Passwords" },
                new MimikatzMethod { Name = "sekurlsa::wdigest", Target = "WDigest Credentials" },
                new MimikatzMethod { Name = "sekurlsa::kerberos", Target = "Kerberos Keys" },
                new MimikatzMethod { Name = "sekurlsa::tspkg", Target = "TsPkg Credentials" },
                new MimikatzMethod { Name = "sekurlsa::livessp", Target = "LiveSSP Credentials" },
                new MimikatzMethod { Name = "lsadump::sam", Target = "SAM Hashes" },
                new MimikatzMethod { Name = "lsadump::cache", Target = "Domain Cached Credentials" }
            };
        }

        private void CheckMimikatzDetectors(List<LSASSAccessResult> results)
        {
            try
            {
                var detectors = new[] { "AMSI", "ETW", "WinDefend", "Sysmon" };

                foreach (var detector in detectors)
                {
                    results.Add(new LSASSAccessResult
                    {
                        TechniqueName = "Mimikatz Detection System",
                        Success = true,
                        Severity = "Medium",
                        Description = $"Detection system present: {detector}",
                        Evidence = $"System: {detector}",
                        DetectionSystem = detector
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check Mimikatz detectors");
            }
        }

        private LSAProtectionStatus CheckLSAProtectionStatus()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (key != null)
                {
                    var runAsPPL = key.GetValue("RunAsPPL");
                    var isProtected = runAsPPL != null && runAsPPL.ToString() == "1";

                    return new LSAProtectionStatus
                    {
                        IsProtected = isProtected,
                        Method = "RunAsPPL Registry Check",
                        Level = isProtected ? "PPL" : "None"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check LSA protection status");
            }

            return new LSAProtectionStatus { IsProtected = false, Method = "Unknown", Level = "None" };
        }

        private void CheckPPLStatus(List<LSASSAccessResult> results)
        {
            try
            {
                var lsassProcesses = Process.GetProcessesByName("lsass");
                foreach (var lsassProcess in lsassProcesses)
                {
                    try
                    {
                        results.Add(new LSASSAccessResult
                        {
                            TechniqueName = "PPL Status Check",
                            Success = true,
                            Severity = "Info",
                            Description = "Protected Process Light status analyzed",
                            Evidence = $"LSASS PID: {lsassProcess.Id}",
                            ProcessId = lsassProcess.Id,
                            PPLEnabled = CheckProcessPPL(lsassProcess.Id)
                        });
                    }
                    finally
                    {
                        lsassProcess?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check PPL status");
            }
        }

        private CredentialGuardStatus GetCredentialGuardStatus()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                if (key != null)
                {
                    var enableVirtualizationBasedSecurity = key.GetValue("EnableVirtualizationBasedSecurity");
                    var requirePlatformSecurityFeatures = key.GetValue("RequirePlatformSecurityFeatures");

                    var isEnabled = enableVirtualizationBasedSecurity?.ToString() == "1";

                    return new CredentialGuardStatus
                    {
                        IsEnabled = isEnabled,
                        Status = isEnabled ? "Running" : "Not Configured",
                        Version = Environment.OSVersion.Version.ToString()
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check Credential Guard status");
            }

            return new CredentialGuardStatus { IsEnabled = false, Status = "Unknown", Version = "Unknown" };
        }

        private void CheckVBSStatus(List<LSASSAccessResult> results)
        {
            try
            {
                results.Add(new LSASSAccessResult
                {
                    TechniqueName = "VBS Status Check",
                    Success = true,
                    Severity = "Info",
                    Description = "Virtualization-based Security status",
                    Evidence = "VBS configuration analyzed",
                    VBSEnabled = IsVBSEnabled()
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check VBS status");
            }
        }

        private WDigestSettings GetWDigestSettings()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest");
                if (key != null)
                {
                    var useLogonCredential = key.GetValue("UseLogonCredential");
                    var negotiable = key.GetValue("Negotiable");

                    return new WDigestSettings
                    {
                        PlaintextEnabled = useLogonCredential?.ToString() == "1",
                        UseLogonCredential = useLogonCredential?.ToString() ?? "0",
                        Negotiable = negotiable?.ToString() ?? "0"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check WDigest settings");
            }

            return new WDigestSettings { PlaintextEnabled = false, UseLogonCredential = "0", Negotiable = "0" };
        }

        private void CheckSSPSettings(List<LSASSAccessResult> results)
        {
            try
            {
                var sspProviders = new[] { "WDigest", "Kerberos", "NTLM", "Negotiate", "Schannel" };

                foreach (var provider in sspProviders)
                {
                    results.Add(new LSASSAccessResult
                    {
                        TechniqueName = "SSP Provider Analysis",
                        Success = true,
                        Severity = "Info",
                        Description = $"Security Support Provider: {provider}",
                        Evidence = $"Provider: {provider}",
                        SSPProvider = provider
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check SSP settings");
            }
        }

        private ProcessDetails GetProcessDetails(Process process)
        {
            try
            {
                return new ProcessDetails
                {
                    WorkingSet = process.WorkingSet64,
                    Threads = process.Threads.Count,
                    Handles = process.HandleCount
                };
            }
            catch
            {
                return new ProcessDetails { WorkingSet = 0, Threads = 0, Handles = 0 };
            }
        }

        private bool CheckProcessPPL(int processId)
        {
            try
            {
                var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
                if (handle != IntPtr.Zero)
                {
                    CloseHandle(handle);
                    return true; // Simplified PPL check
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check PPL for PID: {processId}");
            }

            return false;
        }

        private bool IsVBSEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                if (key != null)
                {
                    var vbsEnabled = key.GetValue("EnableVirtualizationBasedSecurity");
                    return vbsEnabled?.ToString() == "1";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check VBS status");
            }

            return false;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_CREATE_THREAD = 0x0002;

        private class MemoryDumpMethod
        {
            public string Name { get; set; } = string.Empty;
            public string Tool { get; set; } = string.Empty;
            public bool RequiresElevation { get; set; }
        }

        private class ProcessAccessRight
        {
            public string AccessType { get; set; } = string.Empty;
            public bool HasAccess { get; set; }
        }

        private class MimikatzMethod
        {
            public string Name { get; set; } = string.Empty;
            public string Target { get; set; } = string.Empty;
        }

        private class LSAProtectionStatus
        {
            public bool IsProtected { get; set; }
            public string Method { get; set; } = string.Empty;
            public string Level { get; set; } = string.Empty;
        }

        private class CredentialGuardStatus
        {
            public bool IsEnabled { get; set; }
            public string Status { get; set; } = string.Empty;
            public string Version { get; set; } = string.Empty;
        }

        private class WDigestSettings
        {
            public bool PlaintextEnabled { get; set; }
            public string UseLogonCredential { get; set; } = string.Empty;
            public string Negotiable { get; set; } = string.Empty;
        }

        private class ProcessDetails
        {
            public long WorkingSet { get; set; }
            public int Threads { get; set; }
            public int Handles { get; set; }
        }
    }
}