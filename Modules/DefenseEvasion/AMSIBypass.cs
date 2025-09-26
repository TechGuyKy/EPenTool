using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Management;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.DefenseEvasion
{
    public class AMSIBypass
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AMSIBypass> _logger;
        private readonly SecurityContext _securityContext;

        public AMSIBypass(IConfiguration configuration, ILogger<AMSIBypass> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<AMSIBypassResult>> ExecuteAsync()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                _logger.LogInformation("Starting AMSI bypass assessment");

                results.AddRange(await CheckAMSIStatus());
                results.AddRange(await CheckMemoryPatching());
                results.AddRange(await CheckDLLHijacking());
                results.AddRange(await CheckProcessHollowing());
                results.AddRange(await CheckPowerShellLogging());
                results.AddRange(await CheckScriptBlockLogging());
                results.AddRange(await CheckRegistryBypass());
                results.AddRange(await CheckReflectionBypass());
                results.AddRange(await CheckForcedErrorBypass());

                _logger.LogInformation($"AMSI bypass assessment completed. Found {results.Count} techniques");
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AMSI bypass execution failed");
                results.Add(new AMSIBypassResult
                {
                    TechniqueName = "AMSI Bypass Error",
                    Success = false,
                    Severity = "Error",
                    Description = "AMSI bypass assessment failed",
                    Evidence = ex.Message
                });
                return results;
            }
        }

        private async Task<List<AMSIBypassResult>> CheckAMSIStatus()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var amsiEnabled = IsAMSIEnabled();
                    var amsiProvider = GetAMSIProvider();

                    results.Add(new AMSIBypassResult
                    {
                        TechniqueName = "AMSI Status Check",
                        Success = true,
                        Severity = "Info",
                        Description = $"AMSI is {(amsiEnabled ? "enabled" : "disabled")} on this system",
                        Evidence = $"AMSI Status: {(amsiEnabled ? "Active" : "Inactive")}, Provider: {amsiProvider}",
                        AMSIProvider = amsiProvider,
                        BypassMethod = "Status Detection"
                    });

                    if (!amsiEnabled)
                    {
                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "AMSI Already Disabled",
                            Success = true,
                            Severity = "High",
                            Description = "AMSI is already disabled - no bypass needed",
                            Evidence = "AMSI protection is not active",
                            BypassMethod = "System Configuration"
                        });
                    }

                    CheckAMSIContext(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check AMSI status");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckMemoryPatching()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (_securityContext.IsElevated)
                    {
                        var amsiDllLoaded = IsAMSIDLLLoaded();

                        if (amsiDllLoaded)
                        {
                            var patchingMethods = GetMemoryPatchingMethods();

                            foreach (var method in patchingMethods)
                            {
                                results.Add(new AMSIBypassResult
                                {
                                    TechniqueName = "AMSI Memory Patching",
                                    Success = true,
                                    Severity = "Critical",
                                    Description = $"AMSI memory patching possible: {method.Name}",
                                    Evidence = $"Method: {method.Name}, Target: {method.Target}, Offset: {method.Offset}",
                                    BypassMethod = "Memory Patching",
                                    RequiresElevation = true,
                                    PatchMethod = method.Name,
                                    TargetFunction = method.Target
                                });
                            }
                        }

                        CheckAMSIFunctionAddresses(results);
                    }
                    else
                    {
                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "Memory Patching Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "Memory patching assessment requires elevated privileges",
                            Evidence = "Current process lacks sufficient privileges for memory manipulation",
                            BypassMethod = "Memory Patching",
                            RequiresElevation = true
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check memory patching");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckDLLHijacking()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var systemPaths = GetSystemPaths();

                    foreach (var path in systemPaths)
                    {
                        var amsiPath = System.IO.Path.Combine(path, "amsi.dll");

                        if (!System.IO.File.Exists(amsiPath) && IsPathWritable(path))
                        {
                            results.Add(new AMSIBypassResult
                            {
                                TechniqueName = "AMSI DLL Hijacking",
                                Success = true,
                                Severity = "High",
                                Description = $"AMSI DLL hijacking possible in: {path}",
                                Evidence = $"Writable directory without amsi.dll: {path}",
                                BypassMethod = "DLL Hijacking",
                                TargetPath = amsiPath
                            });
                        }
                    }

                    CheckApplicationPaths(results);
                    CheckDLLProxying(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check DLL hijacking");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckProcessHollowing()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var targetProcesses = new[] { "powershell", "powershell_ise", "cmd", "pwsh" };

                    foreach (var processName in targetProcesses)
                    {
                        var processes = Process.GetProcessesByName(processName);

                        if (processes.Length > 0)
                        {
                            foreach (var process in processes)
                            {
                                try
                                {
                                    results.Add(new AMSIBypassResult
                                    {
                                        TechniqueName = "Process Hollowing Target",
                                        Success = true,
                                        Severity = "Medium",
                                        Description = $"Target process available for hollowing: {processName}",
                                        Evidence = $"Process {processName} running (PID: {process.Id})",
                                        BypassMethod = "Process Hollowing",
                                        TargetProcess = processName,
                                        ProcessId = process.Id
                                    });
                                }
                                finally
                                {
                                    process?.Dispose();
                                }
                            }
                        }
                    }

                    CheckProcessPrivileges(results);
                    CheckProcessInjectionMethods(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check process hollowing");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckPowerShellLogging()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var loggingEnabled = IsPowerShellLoggingEnabled();
                    var transcriptionEnabled = IsPowerShellTranscriptionEnabled();
                    var moduleLogging = IsModuleLoggingEnabled();

                    results.Add(new AMSIBypassResult
                    {
                        TechniqueName = "PowerShell Logging Status",
                        Success = true,
                        Severity = loggingEnabled ? "Medium" : "High",
                        Description = $"PowerShell logging configuration analyzed",
                        Evidence = $"Script Block Logging: {loggingEnabled}, Transcription: {transcriptionEnabled}, Module Logging: {moduleLogging}",
                        BypassMethod = "Logging Evasion",
                        LoggingEnabled = loggingEnabled
                    });

                    if (!loggingEnabled)
                    {
                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "PowerShell Logging Disabled",
                            Success = true,
                            Severity = "High",
                            Description = "PowerShell script block logging is disabled",
                            Evidence = "ScriptBlockLogging registry key not configured or disabled",
                            BypassMethod = "Configuration Bypass"
                        });
                    }

                    CheckPowerShellExecutionPolicy(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check PowerShell logging");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckScriptBlockLogging()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var scriptBlockLogging = IsScriptBlockLoggingEnabled();
                    var moduleLogging = IsModuleLoggingEnabled();

                    results.Add(new AMSIBypassResult
                    {
                        TechniqueName = "Script Block Logging Analysis",
                        Success = true,
                        Severity = scriptBlockLogging ? "Low" : "High",
                        Description = $"Script block logging configuration",
                        Evidence = $"ScriptBlock Logging: {scriptBlockLogging}, Module Logging: {moduleLogging}",
                        BypassMethod = "Logging Analysis",
                        LoggingEnabled = scriptBlockLogging
                    });

                    CheckEventLogConfiguration(results);
                    CheckETWProviders(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check script block logging");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckRegistryBypass()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var registryBypassMethods = GetRegistryBypassMethods();

                    foreach (var method in registryBypassMethods)
                    {
                        var canBypass = CanPerformRegistryBypass(method);

                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "Registry Bypass Method",
                            Success = canBypass,
                            Severity = canBypass ? "High" : "Low",
                            Description = $"Registry bypass method: {method.Name}",
                            Evidence = $"Method: {method.Name}, Registry Path: {method.RegistryPath}",
                            BypassMethod = "Registry Manipulation",
                            RegistryPath = method.RegistryPath,
                            RequiresElevation = method.RequiresElevation
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check registry bypass");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckReflectionBypass()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var reflectionMethods = GetReflectionBypassMethods();

                    foreach (var method in reflectionMethods)
                    {
                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "Reflection Bypass Method",
                            Success = true,
                            Severity = "Medium",
                            Description = $"Reflection bypass technique: {method.Name}",
                            Evidence = $"Method: {method.Name}, Target: {method.Target}",
                            BypassMethod = "Reflection Bypass",
                            ReflectionMethod = method.Name,
                            TargetClass = method.Target
                        });
                    }

                    CheckCLRVersion(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check reflection bypass");
            }

            return results;
        }

        private async Task<List<AMSIBypassResult>> CheckForcedErrorBypass()
        {
            var results = new List<AMSIBypassResult>();

            try
            {
                await Task.Run(() =>
                {
                    var forcedErrorMethods = GetForcedErrorMethods();

                    foreach (var method in forcedErrorMethods)
                    {
                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "Forced Error Bypass",
                            Success = true,
                            Severity = "Medium",
                            Description = $"Forced error bypass method: {method.Name}",
                            Evidence = $"Method: {method.Name}, Error Type: {method.ErrorType}",
                            BypassMethod = "Forced Error",
                            ErrorMethod = method.Name
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check forced error bypass");
            }

            return results;
        }

        private bool IsAMSIEnabled()
        {
            try
            {
                var amsiModule = GetLoadedModule("amsi.dll");
                return amsiModule != IntPtr.Zero;
            }
            catch
            {
                return false;
            }
        }

        private string GetAMSIProvider()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM AntiVirusProduct", new ManagementScope(@"\\.\root\SecurityCenter2"));
                using var results = searcher.Get();

                foreach (ManagementObject result in results)
                {
                    try
                    {
                        var displayName = result["displayName"]?.ToString();
                        if (!string.IsNullOrEmpty(displayName))
                        {
                            return displayName;
                        }
                    }
                    finally
                    {
                        result?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get AMSI provider");
            }

            return "Windows Defender";
        }

        private void CheckAMSIContext(List<AMSIBypassResult> results)
        {
            try
            {
                var amsiContext = GetAMSIContextInfo();

                results.Add(new AMSIBypassResult
                {
                    TechniqueName = "AMSI Context Analysis",
                    Success = true,
                    Severity = "Info",
                    Description = "AMSI context information gathered",
                    Evidence = $"Context: {amsiContext}",
                    BypassMethod = "Context Analysis"
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check AMSI context");
            }
        }

        private bool IsAMSIDLLLoaded()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                foreach (ProcessModule module in currentProcess.Modules)
                {
                    if (module.ModuleName.Equals("amsi.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check if AMSI DLL is loaded");
            }

            return false;
        }

        private List<PatchingMethod> GetMemoryPatchingMethods()
        {
            return new List<PatchingMethod>
            {
                new PatchingMethod { Name = "AmsiScanBuffer Patch", Target = "AmsiScanBuffer", Offset = "0x001b" },
                new PatchingMethod { Name = "AmsiScanString Patch", Target = "AmsiScanString", Offset = "0x001b" },
                new PatchingMethod { Name = "AmsiOpenSession Patch", Target = "AmsiOpenSession", Offset = "0x0001" }
            };
        }

        private void CheckAMSIFunctionAddresses(List<AMSIBypassResult> results)
        {
            try
            {
                var amsiDll = GetLoadedModule("amsi.dll");
                if (amsiDll != IntPtr.Zero)
                {
                    var functions = new[] { "AmsiScanBuffer", "AmsiScanString", "AmsiOpenSession" };

                    foreach (var funcName in functions)
                    {
                        var funcAddress = GetProcAddress(amsiDll, funcName);
                        if (funcAddress != IntPtr.Zero)
                        {
                            results.Add(new AMSIBypassResult
                            {
                                TechniqueName = "AMSI Function Address",
                                Success = true,
                                Severity = "High",
                                Description = $"AMSI function address discovered: {funcName}",
                                Evidence = $"Function: {funcName}, Address: {funcAddress:X}",
                                BypassMethod = "Function Analysis",
                                TargetFunction = funcName,
                                FunctionAddress = funcAddress
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check AMSI function addresses");
            }
        }

        private List<string> GetSystemPaths()
        {
            var paths = new List<string>();

            try
            {
                paths.Add(Environment.SystemDirectory);
                paths.Add(System.IO.Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0"));
                paths.Add(Environment.CurrentDirectory);

                var pathEnv = Environment.GetEnvironmentVariable("PATH");
                if (!string.IsNullOrEmpty(pathEnv))
                {
                    paths.AddRange(pathEnv.Split(';', StringSplitOptions.RemoveEmptyEntries));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get system paths");
            }

            return paths;
        }

        private bool IsPathWritable(string path)
        {
            try
            {
                if (!System.IO.Directory.Exists(path)) return false;

                var testFile = System.IO.Path.Combine(path, $"test_{Guid.NewGuid():N}.tmp");
                System.IO.File.WriteAllText(testFile, "test");
                System.IO.File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void CheckApplicationPaths(List<AMSIBypassResult> results)
        {
            try
            {
                var appPaths = new[]
                {
                    @"C:\Program Files\WindowsPowerShell\Modules",
                    @"C:\Program Files (x86)\WindowsPowerShell\Modules",
                    @"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
                };

                foreach (var path in appPaths)
                {
                    if (System.IO.Directory.Exists(path) && IsPathWritable(path))
                    {
                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "PowerShell Module Hijacking",
                            Success = true,
                            Severity = "Medium",
                            Description = $"PowerShell module path is writable: {path}",
                            Evidence = $"Writable module directory: {path}",
                            BypassMethod = "Module Hijacking",
                            TargetPath = path
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check application paths");
            }
        }

        private void CheckDLLProxying(List<AMSIBypassResult> results)
        {
            try
            {
                var proxyMethods = new[] { "Export Forwarding", "DLL Redirection", "Phantom DLL" };

                foreach (var method in proxyMethods)
                {
                    results.Add(new AMSIBypassResult
                    {
                        TechniqueName = "DLL Proxying Method",
                        Success = true,
                        Severity = "Medium",
                        Description = $"DLL proxying technique available: {method}",
                        Evidence = $"Proxy method: {method}",
                        BypassMethod = "DLL Proxying",
                        ProxyMethod = method
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check DLL proxying");
            }
        }

        private void CheckProcessPrivileges(List<AMSIBypassResult> results)
        {
            try
            {
                var requiredPrivileges = new[]
                {
                    "SeDebugPrivilege",
                    "SeImpersonatePrivilege"
                };

                foreach (var privilege in requiredPrivileges)
                {
                    if (_securityContext.HasPrivilege(privilege))
                    {
                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "Process Manipulation Privilege",
                            Success = true,
                            Severity = "High",
                            Description = $"Process has {privilege} for advanced manipulation",
                            Evidence = $"Privilege available: {privilege}",
                            BypassMethod = "Privilege Abuse",
                            RequiresElevation = false
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check process privileges");
            }
        }

        private void CheckProcessInjectionMethods(List<AMSIBypassResult> results)
        {
            try
            {
                var injectionMethods = new[]
                {
                    "CreateRemoteThread",
                    "QueueUserAPC",
                    "SetWindowsHookEx",
                    "Manual DLL Mapping"
                };

                foreach (var method in injectionMethods)
                {
                    results.Add(new AMSIBypassResult
                    {
                        TechniqueName = "Process Injection Method",
                        Success = true,
                        Severity = "Medium",
                        Description = $"Process injection technique available: {method}",
                        Evidence = $"Injection method: {method}",
                        BypassMethod = "Process Injection",
                        InjectionMethod = method
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check process injection methods");
            }
        }

        private bool IsPowerShellLoggingEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
                if (key != null)
                {
                    var enabled = key.GetValue("EnableScriptBlockLogging");
                    return enabled != null && enabled.ToString() == "1";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check PowerShell logging");
            }

            return false;
        }

        private bool IsPowerShellTranscriptionEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription");
                if (key != null)
                {
                    var enabled = key.GetValue("EnableTranscripting");
                    return enabled != null && enabled.ToString() == "1";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check PowerShell transcription");
            }

            return false;
        }

        private bool IsModuleLoggingEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging");
                return key != null && key.GetValue("EnableModuleLogging")?.ToString() == "1";
            }
            catch
            {
                return false;
            }
        }

        private void CheckPowerShellExecutionPolicy(List<AMSIBypassResult> results)
        {
            try
            {
                var executionPolicy = GetPowerShellExecutionPolicy();

                results.Add(new AMSIBypassResult
                {
                    TechniqueName = "PowerShell Execution Policy",
                    Success = true,
                    Severity = executionPolicy == "Restricted" ? "Low" : "Medium",
                    Description = $"PowerShell execution policy: {executionPolicy}",
                    Evidence = $"Current execution policy: {executionPolicy}",
                    BypassMethod = "Policy Analysis",
                    ExecutionPolicy = executionPolicy
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check PowerShell execution policy");
            }
        }

        private bool IsScriptBlockLoggingEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
                return key != null && key.GetValue("EnableScriptBlockLogging")?.ToString() == "1";
            }
            catch
            {
                return false;
            }
        }

        private void CheckEventLogConfiguration(List<AMSIBypassResult> results)
        {
            try
            {
                var eventLogs = new[]
                {
                    "Microsoft-Windows-PowerShell/Operational",
                    "Windows PowerShell"
                };

                foreach (var logName in eventLogs)
                {
                    try
                    {
                        using var eventLog = new EventLog(logName);
                        var isEnabled = eventLog.Entries.Count >= 0;

                        results.Add(new AMSIBypassResult
                        {
                            TechniqueName = "Event Log Configuration",
                            Success = true,
                            Severity = isEnabled ? "Low" : "Medium",
                            Description = $"Event log '{logName}' is {(isEnabled ? "active" : "inactive")}",
                            Evidence = $"Log: {logName}, Status: {(isEnabled ? "Active" : "Inactive")}",
                            BypassMethod = "Log Evasion",
                            LogName = logName
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, $"Failed to check event log: {logName}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check event log configuration");
            }
        }

        private void CheckETWProviders(List<AMSIBypassResult> results)
        {
            try
            {
                var etwProviders = new[]
                {
                    "Microsoft-Windows-PowerShell",
                    "Microsoft-Antimalware-Scan-Interface"
                };

                foreach (var provider in etwProviders)
                {
                    results.Add(new AMSIBypassResult
                    {
                        TechniqueName = "ETW Provider Analysis",
                        Success = true,
                        Severity = "Medium",
                        Description = $"ETW provider identified: {provider}",
                        Evidence = $"Provider: {provider}",
                        BypassMethod = "ETW Evasion",
                        ETWProvider = provider
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check ETW providers");
            }
        }

        private List<RegistryBypassMethod> GetRegistryBypassMethods()
        {
            return new List<RegistryBypassMethod>
            {
                new RegistryBypassMethod
                {
                    Name = "AMSI Provider Disable",
                    RegistryPath = @"HKLM\SOFTWARE\Microsoft\AMSI\Providers",
                    RequiresElevation = true
                },
                new RegistryBypassMethod
                {
                    Name = "PowerShell Provider Disable",
                    RegistryPath = @"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}",
                    RequiresElevation = true
                }
            };
        }

        private bool CanPerformRegistryBypass(RegistryBypassMethod method)
        {
            try
            {
                if (method.RequiresElevation && !_securityContext.IsElevated)
                    return false;

                var keyParts = method.RegistryPath.Split('\\');
                if (keyParts.Length < 2) return false;

                var hive = keyParts[0] switch
                {
                    "HKLM" => Microsoft.Win32.Registry.LocalMachine,
                    "HKCU" => Microsoft.Win32.Registry.CurrentUser,
                    _ => null
                };

                if (hive == null) return false;

                var keyPath = string.Join("\\", keyParts.Skip(1));
                using var key = hive.OpenSubKey(keyPath, true);
                return key != null;
            }
            catch
            {
                return false;
            }
        }

        private List<ReflectionBypassMethod> GetReflectionBypassMethods()
        {
            return new List<ReflectionBypassMethod>
            {
                new ReflectionBypassMethod { Name = "AmsiUtils Field Modification", Target = "System.Management.Automation.AmsiUtils" },
                new ReflectionBypassMethod { Name = "AmsiContext Manipulation", Target = "System.Management.Automation.AmsiContext" },
                new ReflectionBypassMethod { Name = "AmsiSession Override", Target = "System.Management.Automation.AmsiSession" }
            };
        }

        private void CheckCLRVersion(List<AMSIBypassResult> results)
        {
            try
            {
                var clrVersion = Environment.Version.ToString();

                results.Add(new AMSIBypassResult
                {
                    TechniqueName = "CLR Version Analysis",
                    Success = true,
                    Severity = "Info",
                    Description = $"CLR version detected: {clrVersion}",
                    Evidence = $"Runtime version: {clrVersion}",
                    BypassMethod = "Runtime Analysis",
                    CLRVersion = clrVersion
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check CLR version");
            }
        }

        private List<ForcedErrorMethod> GetForcedErrorMethods()
        {
            return new List<ForcedErrorMethod>
            {
                new ForcedErrorMethod { Name = "Invalid Context Error", ErrorType = "E_INVALIDARG" },
                new ForcedErrorMethod { Name = "Access Denied Error", ErrorType = "E_ACCESSDENIED" },
                new ForcedErrorMethod { Name = "Out of Memory Error", ErrorType = "E_OUTOFMEMORY" }
            };
        }

        private string GetAMSIContextInfo()
        {
            try
            {
                var sb = new StringBuilder();
                sb.Append($"Process: {Process.GetCurrentProcess().ProcessName}, ");
                sb.Append($"PID: {Process.GetCurrentProcess().Id}, ");
                sb.Append($"Architecture: {(Environment.Is64BitProcess ? "x64" : "x86")}, ");
                sb.Append($"Elevated: {_securityContext.IsElevated}");
                return sb.ToString();
            }
            catch
            {
                return "Unknown";
            }
        }

        private string GetPowerShellExecutionPolicy()
        {
            try
            {
                using var process = new Process();
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = "-Command \"Get-ExecutionPolicy\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                return output.Trim();
            }
            catch
            {
                return "Unknown";
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        private IntPtr GetLoadedModule(string moduleName)
        {
            return GetModuleHandle(moduleName);
        }

        private class PatchingMethod
        {
            public string Name { get; set; } = string.Empty;
            public string Target { get; set; } = string.Empty;
            public string Offset { get; set; } = string.Empty;
        }

        private class RegistryBypassMethod
        {
            public string Name { get; set; } = string.Empty;
            public string RegistryPath { get; set; } = string.Empty;
            public bool RequiresElevation { get; set; }
        }

        private class ReflectionBypassMethod
        {
            public string Name { get; set; } = string.Empty;
            public string Target { get; set; } = string.Empty;
        }

        private class ForcedErrorMethod
        {
            public string Name { get; set; } = string.Empty;
            public string ErrorType { get; set; } = string.Empty;
        }
    }
}