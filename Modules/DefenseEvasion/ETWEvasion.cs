using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.DefenseEvasion
{
    public class ETWEvasion
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ETWEvasion> _logger;
        private readonly SecurityContext _securityContext;

        public ETWEvasion(IConfiguration configuration, ILogger<ETWEvasion> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<ETWEvasionResult>> ExecuteAsync()
        {
            var results = new List<ETWEvasionResult>();

            try
            {
                _logger.LogInformation("Starting ETW evasion assessment");

                results.AddRange(await CheckETWProviders());
                results.AddRange(await CheckETWConsumers());
                results.AddRange(await CheckProviderUnregistration());
                results.AddRange(await CheckETWPatching());
                results.AddRange(await CheckProviderGUIDs());
                results.AddRange(await CheckTraceSessionManipulation());

                _logger.LogInformation($"ETW evasion assessment completed. Found {results.Count} techniques");
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ETW evasion execution failed");
                results.Add(new ETWEvasionResult
                {
                    TechniqueName = "ETW Evasion Error",
                    Success = false,
                    Severity = "Error",
                    Description = "ETW evasion assessment failed",
                    Evidence = ex.Message
                });
                return results;
            }
        }

        private async Task<List<ETWEvasionResult>> CheckETWProviders()
        {
            var results = new List<ETWEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var etwProviders = GetActiveETWProviders();

                    results.Add(new ETWEvasionResult
                    {
                        TechniqueName = "ETW Provider Enumeration",
                        Success = true,
                        Severity = "Info",
                        Description = $"Found {etwProviders.Count} active ETW providers",
                        Evidence = $"Active ETW providers: {etwProviders.Count}",
                        EvasionMethod = "Provider Discovery",
                        ProviderCount = etwProviders.Count
                    });

                    foreach (var provider in etwProviders)
                    {
                        if (IsSecurityRelevantProvider(provider))
                        {
                            results.Add(new ETWEvasionResult
                            {
                                TechniqueName = "Security-Relevant ETW Provider",
                                Success = true,
                                Severity = "Medium",
                                Description = $"Security-relevant ETW provider active: {provider}",
                                Evidence = $"Provider: {provider}",
                                EvasionMethod = "Provider Targeting",
                                ProviderName = provider
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check ETW providers");
            }

            return results;
        }

        private async Task<List<ETWEvasionResult>> CheckETWConsumers()
        {
            var results = new List<ETWEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var consumers = GetETWConsumers();

                    results.Add(new ETWEvasionResult
                    {
                        TechniqueName = "ETW Consumer Detection",
                        Success = true,
                        Severity = "Info",
                        Description = $"Found {consumers.Count} ETW consumers",
                        Evidence = $"Active ETW consumers: {consumers.Count}",
                        EvasionMethod = "Consumer Analysis",
                        ConsumerCount = consumers.Count
                    });

                    foreach (var consumer in consumers)
                    {
                        results.Add(new ETWEvasionResult
                        {
                            TechniqueName = "ETW Consumer Identified",
                            Success = true,
                            Severity = "Low",
                            Description = $"ETW consumer process: {consumer}",
                            Evidence = $"Consumer: {consumer}",
                            EvasionMethod = "Consumer Targeting",
                            ConsumerProcess = consumer
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check ETW consumers");
            }

            return results;
        }

        private async Task<List<ETWEvasionResult>> CheckProviderUnregistration()
        {
            var results = new List<ETWEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (_securityContext.IsElevated)
                    {
                        var criticalProviders = GetCriticalSecurityProviders();

                        foreach (var provider in criticalProviders)
                        {
                            if (CanUnregisterProvider(provider))
                            {
                                results.Add(new ETWEvasionResult
                                {
                                    TechniqueName = "Provider Unregistration",
                                    Success = true,
                                    Severity = "High",
                                    Description = $"ETW provider can be unregistered: {provider}",
                                    Evidence = $"Unregistrable provider: {provider}",
                                    EvasionMethod = "Provider Unregistration",
                                    ProviderName = provider,
                                    RequiresElevation = true
                                });
                            }
                        }
                    }
                    else
                    {
                        results.Add(new ETWEvasionResult
                        {
                            TechniqueName = "Provider Unregistration Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Provider unregistration assessment requires elevated privileges",
                            Evidence = "Current process lacks administrative privileges",
                            EvasionMethod = "Provider Unregistration",
                            RequiresElevation = true
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check provider unregistration");
            }

            return results;
        }

        private async Task<List<ETWEvasionResult>> CheckETWPatching()
        {
            var results = new List<ETWEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (_securityContext.IsElevated)
                    {
                        var etwFunctions = GetETWFunctions();

                        foreach (var function in etwFunctions)
                        {
                            if (IsFunctionPatchable(function.Key, function.Value))
                            {
                                results.Add(new ETWEvasionResult
                                {
                                    TechniqueName = "ETW Function Patching",
                                    Success = true,
                                    Severity = "Critical",
                                    Description = $"ETW function patchable in memory: {function.Key}",
                                    Evidence = $"Function: {function.Key}, Address: {function.Value:X}",
                                    EvasionMethod = "Memory Patching",
                                    FunctionName = function.Key,
                                    FunctionAddress = function.Value,
                                    RequiresElevation = true
                                });
                            }
                        }
                    }
                    else
                    {
                        results.Add(new ETWEvasionResult
                        {
                            TechniqueName = "Memory Patching Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Memory patching assessment requires elevated privileges",
                            Evidence = "Current process lacks sufficient privileges",
                            EvasionMethod = "Memory Patching",
                            RequiresElevation = true
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check ETW patching");
            }

            return results;
        }

        private async Task<List<ETWEvasionResult>> CheckProviderGUIDs()
        {
            var results = new List<ETWEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var securityProviderGuids = GetSecurityProviderGUIDs();

                    foreach (var guid in securityProviderGuids)
                    {
                        results.Add(new ETWEvasionResult
                        {
                            TechniqueName = "Security Provider GUID",
                            Success = true,
                            Severity = "Medium",
                            Description = $"Security ETW provider GUID identified: {guid.Key}",
                            Evidence = $"Provider: {guid.Key}, GUID: {guid.Value}",
                            EvasionMethod = "GUID Targeting",
                            ProviderName = guid.Key,
                            ProviderGUID = guid.Value
                        });
                    }

                    CheckProviderManifests(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check provider GUIDs");
            }

            return results;
        }

        private async Task<List<ETWEvasionResult>> CheckTraceSessionManipulation()
        {
            var results = new List<ETWEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var traceSessions = GetActiveTraceSessions();

                    results.Add(new ETWEvasionResult
                    {
                        TechniqueName = "Trace Session Enumeration",
                        Success = true,
                        Severity = "Info",
                        Description = $"Found {traceSessions.Count} active trace sessions",
                        Evidence = $"Active sessions: {traceSessions.Count}",
                        EvasionMethod = "Session Discovery",
                        SessionCount = traceSessions.Count
                    });

                    foreach (var session in traceSessions)
                    {
                        if (IsSecurityRelevantSession(session))
                        {
                            results.Add(new ETWEvasionResult
                            {
                                TechniqueName = "Security Trace Session",
                                Success = true,
                                Severity = "High",
                                Description = $"Security-relevant trace session: {session}",
                                Evidence = $"Session: {session}",
                                EvasionMethod = "Session Manipulation",
                                SessionName = session
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check trace session manipulation");
            }

            return results;
        }

        private List<string> GetActiveETWProviders()
        {
            var providers = new List<string>();

            try
            {
                using var searcher = new ManagementObjectSearcher("root\\WMI", "SELECT * FROM EventTrace");
                using var results = searcher.Get();

                foreach (ManagementObject result in results)
                {
                    try
                    {
                        var sessionName = result["SessionName"]?.ToString();
                        if (!string.IsNullOrEmpty(sessionName))
                        {
                            providers.Add(sessionName);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to process ETW provider result");
                    }
                    finally
                    {
                        result?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to enumerate ETW providers");
            }

            return providers;
        }

        private bool IsSecurityRelevantProvider(string providerName)
        {
            var securityProviders = new[]
            {
                "Microsoft-Windows-Kernel-Process",
                "Microsoft-Windows-PowerShell",
                "Microsoft-Windows-WinRM",
                "Microsoft-Windows-Security-Auditing",
                "Microsoft-Antimalware-Scan-Interface",
                "Microsoft-Windows-Threat-Intelligence"
            };

            return Array.Exists(securityProviders, p =>
                providerName.Contains(p, StringComparison.OrdinalIgnoreCase));
        }

        private List<string> GetETWConsumers()
        {
            var consumers = new List<string>();

            try
            {
                var processes = Process.GetProcesses();
                var consumerProcesses = new[] { "svchost", "winlogon", "lsass", "csrss" };

                foreach (var process in processes)
                {
                    try
                    {
                        if (Array.Exists(consumerProcesses, p =>
                            process.ProcessName.Equals(p, StringComparison.OrdinalIgnoreCase)))
                        {
                            consumers.Add($"{process.ProcessName} (PID: {process.Id})");
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
                _logger.LogDebug(ex, "Failed to get ETW consumers");
            }

            return consumers;
        }

        private List<string> GetCriticalSecurityProviders()
        {
            return new List<string>
            {
                "Microsoft-Windows-Kernel-Process",
                "Microsoft-Windows-PowerShell",
                "Microsoft-Antimalware-Scan-Interface",
                "Microsoft-Windows-Security-Auditing",
                "Microsoft-Windows-Threat-Intelligence"
            };
        }

        private bool CanUnregisterProvider(string providerName)
        {
            try
            {
                return _securityContext.IsElevated &&
                       _securityContext.HasPrivilege("SeDebugPrivilege");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check unregistration capability for: {providerName}");
                return false;
            }
        }

        private Dictionary<string, IntPtr> GetETWFunctions()
        {
            var functions = new Dictionary<string, IntPtr>();

            try
            {
                var ntdll = GetModuleHandle("ntdll.dll");
                if (ntdll != IntPtr.Zero)
                {
                    var etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
                    var etwEventWriteFull = GetProcAddress(ntdll, "EtwEventWriteFull");
                    var etwEventRegister = GetProcAddress(ntdll, "EtwEventRegister");

                    if (etwEventWrite != IntPtr.Zero)
                        functions["EtwEventWrite"] = etwEventWrite;
                    if (etwEventWriteFull != IntPtr.Zero)
                        functions["EtwEventWriteFull"] = etwEventWriteFull;
                    if (etwEventRegister != IntPtr.Zero)
                        functions["EtwEventRegister"] = etwEventRegister;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get ETW functions");
            }

            return functions;
        }

        private bool IsFunctionPatchable(string functionName, IntPtr address)
        {
            try
            {
                return address != IntPtr.Zero && _securityContext.IsElevated;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check if function is patchable: {functionName}");
                return false;
            }
        }

        private Dictionary<string, string> GetSecurityProviderGUIDs()
        {
            return new Dictionary<string, string>
            {
                ["Microsoft-Windows-Kernel-Process"] = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
                ["Microsoft-Windows-PowerShell"] = "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
                ["Microsoft-Antimalware-Scan-Interface"] = "{2A576B87-09A7-520E-C21A-4942F0271D67}",
                ["Microsoft-Windows-Security-Auditing"] = "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                ["Microsoft-Windows-Threat-Intelligence"] = "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"
            };
        }

        private void CheckProviderManifests(List<ETWEvasionResult> results)
        {
            try
            {
                var manifestPaths = new[]
                {
                    @"C:\Windows\System32\WinEvt\Publishers",
                    @"C:\Windows\System32\winevt\Publishers"
                };

                foreach (var path in manifestPaths)
                {
                    if (System.IO.Directory.Exists(path))
                    {
                        var manifestFiles = System.IO.Directory.GetFiles(path, "*.man", System.IO.SearchOption.TopDirectoryOnly);

                        results.Add(new ETWEvasionResult
                        {
                            TechniqueName = "ETW Provider Manifests",
                            Success = true,
                            Severity = "Low",
                            Description = $"Found {manifestFiles.Length} ETW provider manifest files",
                            Evidence = $"Manifest path: {path}, Files: {manifestFiles.Length}",
                            EvasionMethod = "Manifest Analysis"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check provider manifests");
            }
        }

        private List<string> GetActiveTraceSessions()
        {
            var sessions = new List<string>();

            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "logman.exe",
                    Arguments = "query -ets",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (!line.Contains("Data Collector Set") &&
                            !line.Contains("---") &&
                            !string.IsNullOrWhiteSpace(line.Trim()))
                        {
                            sessions.Add(line.Trim());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get active trace sessions");
            }

            return sessions;
        }

        private bool IsSecurityRelevantSession(string sessionName)
        {
            var securitySessions = new[]
            {
                "Eventlog-Security",
                "Eventlog-System",
                "Eventlog-Application",
                "Microsoft-Windows-Kernel-Logger",
                "WinHttpLog"
            };

            return Array.Exists(securitySessions, s =>
                sessionName.Contains(s, StringComparison.OrdinalIgnoreCase));
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
}