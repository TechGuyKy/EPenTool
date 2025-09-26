using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.DefenseEvasion
{
    public class ProcessInjection
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ProcessInjection> _logger;
        private readonly SecurityContext _securityContext;

        public ProcessInjection(IConfiguration configuration, ILogger<ProcessInjection> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<ProcessInjectionResult>> ExecuteAsync()
        {
            var results = new List<ProcessInjectionResult>();

            try
            {
                _logger.LogInformation("Starting process injection assessment");

                results.AddRange(await CheckDLLInjection());
                results.AddRange(await CheckReflectiveDLLInjection());
                results.AddRange(await CheckProcessDoppelganger());
                results.AddRange(await CheckAtomBombing());
                results.AddRange(await CheckManualDLLMapping());
                results.AddRange(await CheckThreadExecution());

                _logger.LogInformation($"Process injection assessment completed. Found {results.Count} techniques");
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Process injection execution failed");
                results.Add(new ProcessInjectionResult
                {
                    TechniqueName = "Process Injection Error",
                    Success = false,
                    Severity = "Error",
                    Description = "Process injection assessment failed",
                    Evidence = ex.Message
                });
                return results;
            }
        }

        private async Task<List<ProcessInjectionResult>> CheckDLLInjection()
        {
            var results = new List<ProcessInjectionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var targetProcesses = GetInjectionTargets();

                    results.Add(new ProcessInjectionResult
                    {
                        TechniqueName = "DLL Injection Assessment",
                        Success = true,
                        Severity = "Info",
                        Description = $"Found {targetProcesses.Count} potential injection targets",
                        Evidence = $"Target processes: {string.Join(", ", targetProcesses)}",
                        InjectionMethod = "DLL Injection",
                        TargetProcesses = targetProcesses
                    });

                    foreach (var target in targetProcesses)
                    {
                        if (CanInjectIntoProcess(target))
                        {
                            results.Add(new ProcessInjectionResult
                            {
                                TechniqueName = "DLL Injection Capability",
                                Success = true,
                                Severity = "High",
                                Description = $"DLL injection possible into: {target}",
                                Evidence = $"Target process: {target} has suitable permissions",
                                InjectionMethod = "DLL Injection",
                                TargetProcess = target,
                                RequiredPrivileges = GetRequiredPrivileges("DLL Injection")
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check DLL injection");
            }

            return results;
        }

        private async Task<List<ProcessInjectionResult>> CheckReflectiveDLLInjection()
        {
            var results = new List<ProcessInjectionResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (HasRequiredPrivileges("Reflective DLL Injection"))
                    {
                        var targetProcesses = GetHighValueTargets();

                        foreach (var target in targetProcesses)
                        {
                            results.Add(new ProcessInjectionResult
                            {
                                TechniqueName = "Reflective DLL Injection",
                                Success = true,
                                Severity = "Critical",
                                Description = $"Reflective DLL injection possible into: {target}",
                                Evidence = $"Target: {target}, Method: In-memory DLL loading",
                                InjectionMethod = "Reflective DLL Injection",
                                TargetProcess = target,
                                RequiredPrivileges = GetRequiredPrivileges("Reflective DLL Injection"),
                                StealthLevel = "High"
                            });
                        }
                    }
                    else
                    {
                        results.Add(new ProcessInjectionResult
                        {
                            TechniqueName = "Reflective DLL Injection Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Reflective DLL injection requires elevated privileges",
                            Evidence = "Insufficient privileges for reflective injection",
                            InjectionMethod = "Reflective DLL Injection",
                            RequiredPrivileges = GetRequiredPrivileges("Reflective DLL Injection")
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check reflective DLL injection");
            }

            return results;
        }

        private async Task<List<ProcessInjectionResult>> CheckProcessDoppelganger()
        {
            var results = new List<ProcessInjectionResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (_securityContext.IsElevated)
                    {
                        var legitimateProcesses = GetLegitimateProcesses();

                        foreach (var process in legitimateProcesses)
                        {
                            results.Add(new ProcessInjectionResult
                            {
                                TechniqueName = "Process Doppelganger",
                                Success = true,
                                Severity = "Critical",
                                Description = $"Process doppelganger possible with: {process}",
                                Evidence = $"Target: {process}, Method: Transacted file manipulation",
                                InjectionMethod = "Process Doppelganger",
                                TargetProcess = process,
                                RequiredPrivileges = GetRequiredPrivileges("Process Doppelganger"),
                                StealthLevel = "Very High"
                            });
                        }
                    }
                    else
                    {
                        results.Add(new ProcessInjectionResult
                        {
                            TechniqueName = "Process Doppelganger Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Process doppelganger requires elevated privileges",
                            Evidence = "Administrative privileges required",
                            InjectionMethod = "Process Doppelganger",
                            RequiredPrivileges = GetRequiredPrivileges("Process Doppelganger")
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check process doppelganger");
            }

            return results;
        }

        private async Task<List<ProcessInjectionResult>> CheckAtomBombing()
        {
            var results = new List<ProcessInjectionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var atomTableAccess = CanAccessGlobalAtomTable();

                    results.Add(new ProcessInjectionResult
                    {
                        TechniqueName = "Atom Bombing Assessment",
                        Success = atomTableAccess,
                        Severity = atomTableAccess ? "High" : "Low",
                        Description = $"Atom bombing technique {(atomTableAccess ? "available" : "not available")}",
                        Evidence = $"Global atom table access: {(atomTableAccess ? "Granted" : "Denied")}",
                        InjectionMethod = "Atom Bombing",
                        RequiredPrivileges = GetRequiredPrivileges("Atom Bombing"),
                        StealthLevel = "High"
                    });

                    if (atomTableAccess)
                    {
                        var targetProcesses = GetAtomBombingTargets();
                        foreach (var target in targetProcesses)
                        {
                            results.Add(new ProcessInjectionResult
                            {
                                TechniqueName = "Atom Bombing Target",
                                Success = true,
                                Severity = "High",
                                Description = $"Atom bombing possible into: {target}",
                                Evidence = $"Target: {target}, Method: Global atom table manipulation",
                                InjectionMethod = "Atom Bombing",
                                TargetProcess = target,
                                StealthLevel = "High"
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check atom bombing");
            }

            return results;
        }

        private async Task<List<ProcessInjectionResult>> CheckManualDLLMapping()
        {
            var results = new List<ProcessInjectionResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (HasRequiredPrivileges("Manual DLL Mapping"))
                    {
                        var targetProcesses = GetMappingTargets();

                        foreach (var target in targetProcesses)
                        {
                            results.Add(new ProcessInjectionResult
                            {
                                TechniqueName = "Manual DLL Mapping",
                                Success = true,
                                Severity = "Critical",
                                Description = $"Manual DLL mapping possible into: {target}",
                                Evidence = $"Target: {target}, Method: Manual PE mapping",
                                InjectionMethod = "Manual DLL Mapping",
                                TargetProcess = target,
                                RequiredPrivileges = GetRequiredPrivileges("Manual DLL Mapping"),
                                StealthLevel = "Very High"
                            });
                        }
                    }
                    else
                    {
                        results.Add(new ProcessInjectionResult
                        {
                            TechniqueName = "Manual DLL Mapping Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Manual DLL mapping requires specific privileges",
                            Evidence = "SeDebugPrivilege or process ownership required",
                            InjectionMethod = "Manual DLL Mapping",
                            RequiredPrivileges = GetRequiredPrivileges("Manual DLL Mapping")
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check manual DLL mapping");
            }

            return results;
        }

        private async Task<List<ProcessInjectionResult>> CheckThreadExecution()
        {
            var results = new List<ProcessInjectionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var threadTechniques = GetThreadExecutionTechniques();

                    foreach (var technique in threadTechniques)
                    {
                        var availability = IsThreadTechniqueAvailable(technique);

                        results.Add(new ProcessInjectionResult
                        {
                            TechniqueName = "Thread Execution Technique",
                            Success = availability,
                            Severity = availability ? "High" : "Low",
                            Description = $"Thread execution technique: {technique}",
                            Evidence = $"Technique: {technique}, Available: {availability}",
                            InjectionMethod = "Thread Execution",
                            ThreadTechnique = technique,
                            RequiredPrivileges = GetRequiredPrivileges("Thread Execution")
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check thread execution");
            }

            return results;
        }

        private List<string> GetInjectionTargets()
        {
            var targets = new List<string>();

            try
            {
                var commonTargets = new[]
                {
                    "explorer", "svchost", "winlogon", "csrss", "lsass",
                    "powershell", "cmd", "notepad", "calc"
                };

                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        if (Array.Exists(commonTargets, t =>
                            process.ProcessName.Equals(t, StringComparison.OrdinalIgnoreCase)))
                        {
                            targets.Add($"{process.ProcessName} (PID: {process.Id})");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, $"Failed to check process: {process.ProcessName}");
                    }
                    finally
                    {
                        process?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get injection targets");
            }

            return targets;
        }

        private bool CanInjectIntoProcess(string processInfo)
        {
            try
            {
                if (processInfo.Contains("PID:"))
                {
                    var pidStr = processInfo.Split('(')[1].Split(':')[1].Split(')')[0].Trim();
                    if (int.TryParse(pidStr, out int pid))
                    {
                        var process = Process.GetProcessById(pid);

                        // Check if we can open the process with required access
                        var handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                        if (handle != IntPtr.Zero)
                        {
                            CloseHandle(handle);
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check injection capability for: {processInfo}");
            }

            return false;
        }

        private List<string> GetRequiredPrivileges(string technique)
        {
            return technique switch
            {
                "DLL Injection" => new List<string> { "SeDebugPrivilege" },
                "Reflective DLL Injection" => new List<string> { "SeDebugPrivilege", "SeImpersonatePrivilege" },
                "Process Doppelganger" => new List<string> { "SeDebugPrivilege", "SeBackupPrivilege" },
                "Atom Bombing" => new List<string> { "SeImpersonatePrivilege" },
                "Manual DLL Mapping" => new List<string> { "SeDebugPrivilege" },
                "Thread Execution" => new List<string> { "SeDebugPrivilege" },
                _ => new List<string>()
            };
        }

        private bool HasRequiredPrivileges(string technique)
        {
            var requiredPrivs = GetRequiredPrivileges(technique);
            return requiredPrivs.All(priv => _securityContext.HasPrivilege(priv));
        }

        private List<string> GetHighValueTargets()
        {
            return new List<string>
            {
                "explorer.exe",
                "svchost.exe",
                "winlogon.exe",
                "services.exe"
            };
        }

        private List<string> GetLegitimateProcesses()
        {
            return new List<string>
            {
                "notepad.exe",
                "calc.exe",
                "mspaint.exe",
                "explorer.exe"
            };
        }

        private bool CanAccessGlobalAtomTable()
        {
            try
            {
                var testAtom = GlobalAddAtom("TestAtom");
                if (testAtom != 0)
                {
                    GlobalDeleteAtom(testAtom);
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to test global atom table access");
            }

            return false;
        }

        private List<string> GetAtomBombingTargets()
        {
            return new List<string>
            {
                "explorer.exe",
                "notepad.exe",
                "calc.exe"
            };
        }

        private List<string> GetMappingTargets()
        {
            return new List<string>
            {
                "svchost.exe",
                "explorer.exe",
                "winlogon.exe",
                "powershell.exe"
            };
        }

        private List<string> GetThreadExecutionTechniques()
        {
            return new List<string>
            {
                "CreateRemoteThread",
                "NtCreateThreadEx",
                "RtlCreateUserThread",
                "SetWindowsHookEx",
                "QueueUserAPC"
            };
        }

        private bool IsThreadTechniqueAvailable(string technique)
        {
            try
            {
                return technique switch
                {
                    "CreateRemoteThread" => _securityContext.HasPrivilege("SeDebugPrivilege"),
                    "NtCreateThreadEx" => _securityContext.IsElevated,
                    "RtlCreateUserThread" => _securityContext.HasPrivilege("SeDebugPrivilege"),
                    "SetWindowsHookEx" => true, // Generally available
                    "QueueUserAPC" => _securityContext.HasPrivilege("SeDebugPrivilege"),
                    _ => false
                };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check technique availability: {technique}");
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern ushort GlobalAddAtom(string lpString);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern ushort GlobalDeleteAtom(ushort nAtom);

        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    }
}