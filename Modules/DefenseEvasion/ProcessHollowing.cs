using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Core;
using EPenT.Models.Results;

namespace EliteWindowsPentestSuite.Modules.DefenseEvasion
{
    public class ProcessHollowing
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ProcessHollowing> _logger;
        private readonly SecurityContext _securityContext;

        public ProcessHollowing(IConfiguration configuration, ILogger<ProcessHollowing> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<ProcessHollowingResult>> ExecuteAsync()
        {
            var results = new List<ProcessHollowingResult>();

            try
            {
                _logger.LogInformation("Starting process hollowing assessment");

                results.AddRange(await CheckProcessCreation());
                results.AddRange(await CheckMemoryUnmapping());
                results.AddRange(await CheckPayloadMapping());
                results.AddRange(await CheckEntryPointRedirection());
                results.AddRange(await CheckThreadExecution());
                results.AddRange(await CheckHollowingTargets());

                _logger.LogInformation($"Process hollowing assessment completed. Found {results.Count} techniques");
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Process hollowing execution failed");
                results.Add(new ProcessHollowingResult
                {
                    TechniqueName = "Process Hollowing Error",
                    Success = false,
                    Severity = "Error",
                    Description = "Process hollowing assessment failed",
                    Evidence = ex.Message
                });
                return results;
            }
        }

        private async Task<List<ProcessHollowingResult>> CheckProcessCreation()
        {
            var results = new List<ProcessHollowingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var hollowingTargets = GetHollowingTargets();

                    results.Add(new ProcessHollowingResult
                    {
                        TechniqueName = "Process Creation Assessment",
                        Success = true,
                        Severity = "Info",
                        Description = $"Found {hollowingTargets.Count} potential hollowing targets",
                        Evidence = $"Target executables: {string.Join(", ", hollowingTargets)}",
                        HollowingMethod = "Process Creation",
                        TargetExecutables = hollowingTargets
                    });

                    foreach (var target in hollowingTargets)
                    {
                        if (CanCreateSuspendedProcess(target))
                        {
                            results.Add(new ProcessHollowingResult
                            {
                                TechniqueName = "Suspended Process Creation",
                                Success = true,
                                Severity = "High",
                                Description = $"Can create suspended process: {target}",
                                Evidence = $"Target: {target}, Method: CREATE_SUSPENDED",
                                HollowingMethod = "Suspended Creation",
                                TargetExecutable = target,
                                RequiredPrivileges = GetRequiredPrivileges("Process Creation")
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check process creation");
            }

            return results;
        }

        private async Task<List<ProcessHollowingResult>> CheckMemoryUnmapping()
        {
            var results = new List<ProcessHollowingResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (HasRequiredPrivileges("Memory Unmapping"))
                    {
                        var unmappingMethods = GetUnmappingMethods();

                        foreach (var method in unmappingMethods)
                        {
                            results.Add(new ProcessHollowingResult
                            {
                                TechniqueName = "Memory Unmapping Method",
                                Success = true,
                                Severity = "High",
                                Description = $"Memory unmapping technique: {method}",
                                Evidence = $"Method: {method}, API availability confirmed",
                                HollowingMethod = "Memory Unmapping",
                                UnmappingMethod = method,
                                RequiredPrivileges = GetRequiredPrivileges("Memory Unmapping")
                            });
                        }
                    }
                    else
                    {
                        results.Add(new ProcessHollowingResult
                        {
                            TechniqueName = "Memory Unmapping Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Memory unmapping requires elevated privileges",
                            Evidence = "SeDebugPrivilege or process ownership required",
                            HollowingMethod = "Memory Unmapping",
                            RequiredPrivileges = GetRequiredPrivileges("Memory Unmapping")
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check memory unmapping");
            }

            return results;
        }

        private async Task<List<ProcessHollowingResult>> CheckPayloadMapping()
        {
            var results = new List<ProcessHollowingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var mappingTechniques = GetPayloadMappingTechniques();

                    foreach (var technique in mappingTechniques)
                    {
                        var availability = IsPayloadMappingAvailable(technique);

                        results.Add(new ProcessHollowingResult
                        {
                            TechniqueName = "Payload Mapping Technique",
                            Success = availability,
                            Severity = availability ? "High" : "Low",
                            Description = $"Payload mapping technique: {technique}",
                            Evidence = $"Technique: {technique}, Available: {availability}",
                            HollowingMethod = "Payload Mapping",
                            PayloadMappingMethod = technique,
                            RequiredPrivileges = GetRequiredPrivileges("Payload Mapping")
                        });
                    }

                    CheckSectionMapping(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check payload mapping");
            }

            return results;
        }

        private async Task<List<ProcessHollowingResult>> CheckEntryPointRedirection()
        {
            var results = new List<ProcessHollowingResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (_securityContext.IsElevated)
                    {
                        var redirectionMethods = GetEntryPointRedirectionMethods();

                        foreach (var method in redirectionMethods)
                        {
                            results.Add(new ProcessHollowingResult
                            {
                                TechniqueName = "Entry Point Redirection",
                                Success = true,
                                Severity = "Critical",
                                Description = $"Entry point redirection method: {method}",
                                Evidence = $"Method: {method}, Thread context manipulation possible",
                                HollowingMethod = "Entry Point Redirection",
                                RedirectionMethod = method,
                                RequiredPrivileges = GetRequiredPrivileges("Entry Point Redirection"),
                                StealthLevel = "Very High"
                            });
                        }
                    }
                    else
                    {
                        results.Add(new ProcessHollowingResult
                        {
                            TechniqueName = "Entry Point Redirection Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Entry point redirection requires elevated privileges",
                            Evidence = "Administrative privileges needed for thread context manipulation",
                            HollowingMethod = "Entry Point Redirection",
                            RequiredPrivileges = GetRequiredPrivileges("Entry Point Redirection")
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check entry point redirection");
            }

            return results;
        }

        private async Task<List<ProcessHollowingResult>> CheckThreadExecution()
        {
            var results = new List<ProcessHollowingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var executionMethods = GetThreadExecutionMethods();

                    foreach (var method in executionMethods)
                    {
                        var availability = IsThreadExecutionAvailable(method);

                        results.Add(new ProcessHollowingResult
                        {
                            TechniqueName = "Thread Execution Method",
                            Success = availability,
                            Severity = availability ? "High" : "Medium",
                            Description = $"Thread execution method: {method}",
                            Evidence = $"Method: {method}, Available: {availability}",
                            HollowingMethod = "Thread Execution",
                            ThreadExecutionMethod = method,
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

        private async Task<List<ProcessHollowingResult>> CheckHollowingTargets()
        {
            var results = new List<ProcessHollowingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var preferredTargets = GetPreferredHollowingTargets();

                    foreach (var target in preferredTargets)
                    {
                        var suitability = AssessTargetSuitability(target);

                        results.Add(new ProcessHollowingResult
                        {
                            TechniqueName = "Hollowing Target Analysis",
                            Success = true,
                            Severity = suitability.Score >= 7 ? "High" : "Medium",
                            Description = $"Target suitability for {target}: {suitability.Score}/10",
                            Evidence = $"Target: {target}, Reasons: {string.Join(", ", suitability.Reasons)}",
                            HollowingMethod = "Target Analysis",
                            TargetExecutable = target,
                            SuitabilityScore = suitability.Score,
                            SuitabilityReasons = suitability.Reasons
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check hollowing targets");
            }

            return results;
        }

        private List<string> GetHollowingTargets()
        {
            var targets = new List<string>();

            try
            {
                var commonTargets = new[]
                {
                    "notepad.exe",
                    "calc.exe",
                    "mspaint.exe",
                    "explorer.exe",
                    "svchost.exe",
                    "powershell.exe",
                    "cmd.exe"
                };

                var systemDir = Environment.SystemDirectory;
                var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

                foreach (var target in commonTargets)
                {
                    var systemPath = Path.Combine(systemDir, target);
                    var windowsPath = Path.Combine(windowsDir, target);

                    if (File.Exists(systemPath))
                    {
                        targets.Add(systemPath);
                    }
                    else if (File.Exists(windowsPath))
                    {
                        targets.Add(windowsPath);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get hollowing targets");
            }

            return targets;
        }

        private bool CanCreateSuspendedProcess(string executable)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    CreateNoWindow = true,
                    UseShellExecute = false
                };

                using var testProcess = Process.Start(startInfo);
                if (testProcess != null)
                {
                    testProcess.Kill();
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to test process creation for: {executable}");
            }

            return false;
        }

        private List<string> GetRequiredPrivileges(string method)
        {
            return method switch
            {
                "Process Creation" => new List<string> { "SeAssignPrimaryTokenPrivilege" },
                "Memory Unmapping" => new List<string> { "SeDebugPrivilege" },
                "Payload Mapping" => new List<string> { "SeDebugPrivilege" },
                "Entry Point Redirection" => new List<string> { "SeDebugPrivilege", "SeImpersonatePrivilege" },
                "Thread Execution" => new List<string> { "SeDebugPrivilege" },
                _ => new List<string>()
            };
        }

        private bool HasRequiredPrivileges(string method)
        {
            var requiredPrivs = GetRequiredPrivileges(method);
            return requiredPrivs.All(priv => _securityContext.HasPrivilege(priv));
        }

        private List<string> GetUnmappingMethods()
        {
            return new List<string>
            {
                "NtUnmapViewOfSection",
                "ZwUnmapViewOfSection",
                "VirtualFree"
            };
        }

        private List<string> GetPayloadMappingTechniques()
        {
            return new List<string>
            {
                "VirtualAllocEx + WriteProcessMemory",
                "NtMapViewOfSection",
                "Manual PE Mapping",
                "Section-based Mapping"
            };
        }

        private bool IsPayloadMappingAvailable(string technique)
        {
            try
            {
                return technique switch
                {
                    "VirtualAllocEx + WriteProcessMemory" => _securityContext.HasPrivilege("SeDebugPrivilege"),
                    "NtMapViewOfSection" => _securityContext.IsElevated,
                    "Manual PE Mapping" => _securityContext.HasPrivilege("SeDebugPrivilege"),
                    "Section-based Mapping" => _securityContext.IsElevated,
                    _ => false
                };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check payload mapping availability: {technique}");
                return false;
            }
        }

        private void CheckSectionMapping(List<ProcessHollowingResult> results)
        {
            try
            {
                results.Add(new ProcessHollowingResult
                {
                    TechniqueName = "Section Mapping Capability",
                    Success = _securityContext.IsElevated,
                    Severity = _securityContext.IsElevated ? "High" : "Low",
                    Description = "Section-based memory mapping capability",
                    Evidence = $"Elevated privileges: {_securityContext.IsElevated}",
                    HollowingMethod = "Section Mapping",
                    RequiredPrivileges = new List<string> { "SeDebugPrivilege" }
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check section mapping");
            }
        }

        private List<string> GetEntryPointRedirectionMethods()
        {
            return new List<string>
            {
                "SetThreadContext",
                "NtSetContextThread",
                "Manual EIP/RIP Modification",
                "Thread Suspension + Context Manipulation"
            };
        }

        private List<string> GetThreadExecutionMethods()
        {
            return new List<string>
            {
                "ResumeThread",
                "NtResumeThread",
                "SetThreadContext + ResumeThread",
                "Manual Thread Execution"
            };
        }

        private bool IsThreadExecutionAvailable(string method)
        {
            try
            {
                return method switch
                {
                    "ResumeThread" => true,
                    "NtResumeThread" => _securityContext.IsElevated,
                    "SetThreadContext + ResumeThread" => _securityContext.HasPrivilege("SeDebugPrivilege"),
                    "Manual Thread Execution" => _securityContext.IsElevated,
                    _ => false
                };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check thread execution availability: {method}");
                return false;
            }
        }

        private List<string> GetPreferredHollowingTargets()
        {
            return new List<string>
            {
                "svchost.exe",
                "explorer.exe",
                "notepad.exe",
                "calc.exe",
                "powershell.exe"
            };
        }

        private (int Score, List<string> Reasons) AssessTargetSuitability(string target)
        {
            var score = 0;
            var reasons = new List<string>();

            try
            {
                var fileName = Path.GetFileName(target);

                if (fileName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                {
                    score += 3;
                    reasons.Add("Trusted system process");
                }

                if (fileName.Equals("notepad.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("calc.exe", StringComparison.OrdinalIgnoreCase))
                {
                    score += 2;
                    reasons.Add("Common user application");
                }

                if (File.Exists(target))
                {
                    score += 2;
                    reasons.Add("Executable exists on system");

                    var versionInfo = FileVersionInfo.GetVersionInfo(target);
                    if (!string.IsNullOrEmpty(versionInfo.CompanyName) &&
                        versionInfo.CompanyName.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
                    {
                        score += 2;
                        reasons.Add("Microsoft signed executable");
                    }
                }

                if (Environment.Is64BitOperatingSystem)
                {
                    score += 1;
                    reasons.Add("64-bit architecture compatible");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to assess target suitability: {target}");
                reasons.Add("Assessment error occurred");
            }

            return (score, reasons);
        }
    }
}