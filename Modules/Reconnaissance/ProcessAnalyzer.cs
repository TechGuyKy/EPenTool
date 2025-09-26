using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Management;
using System.Linq;
using System.IO;
using System.Security.Principal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Core;
using EPenT.Models.System;
using EPenT.Models.Vulnerabilities;

namespace EPenT.Modules.Reconnaissance
{
    public class ProcessAnalyzer
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ProcessAnalyzer> _logger;
        private readonly SecurityContext _securityContext;

        public ProcessAnalyzer(IConfiguration configuration, ILogger<ProcessAnalyzer> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<ProcessInformation>> AnalyzeProcessesAsync()
        {
            var processes = new List<ProcessInformation>();

            try
            {
                _logger.LogInformation("Starting process analysis");

                var systemProcesses = await GetSystemProcessesAsync();
                var wmiProcesses = await GetWMIProcessesAsync();

                processes.AddRange(systemProcesses);

                foreach (var wmiProcess in wmiProcesses)
                {
                    var existingProcess = processes.FirstOrDefault(p => p.ProcessId == wmiProcess.ProcessId);
                    if (existingProcess != null)
                    {
                        MergeProcessInformation(existingProcess, wmiProcess);
                    }
                    else
                    {
                        processes.Add(wmiProcess);
                    }
                }

                await AnalyzeProcessVulnerabilities(processes);
                await AnalyzeProcessPrivileges(processes);

                _logger.LogInformation($"Process analysis completed. Analyzed {processes.Count} processes");
                return processes.OrderBy(p => p.ProcessName).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Process analysis failed");
                return processes;
            }
        }

        private async Task<List<ProcessInformation>> GetSystemProcessesAsync()
        {
            var processes = new List<ProcessInformation>();

            try
            {
                await Task.Run(() =>
                {
                    var systemProcesses = Process.GetProcesses();

                    foreach (var process in systemProcesses)
                    {
                        try
                        {
                            var processInfo = new ProcessInformation
                            {
                                ProcessId = process.Id,
                                ProcessName = process.ProcessName,
                                StartTime = GetProcessStartTime(process),
                                BasePriority = process.BasePriority,
                                PriorityClass = GetProcessPriorityClass(process),
                                WorkingSet = process.WorkingSet64,
                                PagedMemorySize = process.PagedMemorySize64,
                                VirtualMemorySize = process.VirtualMemorySize64,
                                ThreadCount = process.Threads.Count,
                                HandleCount = process.HandleCount,
                                SessionId = process.SessionId,
                                MainWindowTitle = process.MainWindowTitle,
                                HasMainWindow = process.MainWindowHandle != IntPtr.Zero,
                                IsResponding = GetProcessResponding(process),
                                ExecutablePath = GetProcessExecutablePath(process),
                                CommandLine = string.Empty,
                                Owner = string.Empty,
                                ParentProcessId = 0,
                                Vulnerabilities = new List<ProcessVulnerability>()
                            };

                            processes.Add(processInfo);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, $"Failed to get details for process: {process.ProcessName} (PID: {process.Id})");
                        }
                        finally
                        {
                            process?.Dispose();
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate system processes");
            }

            return processes;
        }

        private async Task<List<ProcessInformation>> GetWMIProcessesAsync()
        {
            var processes = new List<ProcessInformation>();

            try
            {
                await Task.Run(() =>
                {
                    using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process");
                    using var results = searcher.Get();

                    foreach (ManagementObject process in results)
                    {
                        try
                        {
                            var processInfo = new ProcessInformation
                            {
                                ProcessId = Convert.ToInt32(process["ProcessId"] ?? 0),
                                ProcessName = process["Name"]?.ToString() ?? "Unknown",
                                ExecutablePath = process["ExecutablePath"]?.ToString() ?? "Unknown",
                                CommandLine = process["CommandLine"]?.ToString() ?? string.Empty,
                                CreationDate = ManagementDateTimeConverter.ToDateTime(process["CreationDate"]?.ToString() ?? DateTime.MinValue.ToString()),
                                ParentProcessId = Convert.ToInt32(process["ParentProcessId"] ?? 0),
                                ThreadCount = Convert.ToInt32(process["ThreadCount"] ?? 0),
                                HandleCount = Convert.ToInt32(process["HandleCount"] ?? 0),
                                WorkingSet = Convert.ToInt64(process["WorkingSetSize"] ?? 0),
                                VirtualMemorySize = Convert.ToInt64(process["VirtualSize"] ?? 0),
                                PagedMemorySize = Convert.ToInt64(process["PageFileUsage"] ?? 0),
                                SessionId = Convert.ToInt32(process["SessionId"] ?? 0),
                                Owner = GetProcessOwner(process),
                                Description = process["Description"]?.ToString() ?? "No description",
                                Vulnerabilities = new List<ProcessVulnerability>()
                            };

                            processes.Add(processInfo);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "Failed to process WMI process object");
                        }
                        finally
                        {
                            process?.Dispose();
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate WMI processes");
            }

            return processes;
        }

        private async Task AnalyzeProcessVulnerabilities(List<ProcessInformation> processes)
        {
            try
            {
                await Task.Run(() =>
                {
                    foreach (var process in processes)
                    {
                        if (HasUnquotedExecutablePath(process))
                        {
                            process.Vulnerabilities.Add(new ProcessVulnerability
                            {
                                Type = "Unquoted Executable Path",
                                Severity = "Medium",
                                Description = "Process executable path contains spaces but is not quoted",
                                ProcessName = process.ProcessName,
                                ProcessId = process.ProcessId,
                                ExecutablePath = process.ExecutablePath,
                                Exploitable = true
                            });
                        }

                        if (IsRunningFromTempDirectory(process))
                        {
                            process.Vulnerabilities.Add(new ProcessVulnerability
                            {
                                Type = "Suspicious Location",
                                Severity = "High",
                                Description = "Process running from temporary or suspicious directory",
                                ProcessName = process.ProcessName,
                                ProcessId = process.ProcessId,
                                ExecutablePath = process.ExecutablePath,
                                Exploitable = false
                            });
                        }

                        if (IsRunningAsSystem(process))
                        {
                            process.Vulnerabilities.Add(new ProcessVulnerability
                            {
                                Type = "Privileged Process",
                                Severity = "Low",
                                Description = "Process running under privileged account",
                                ProcessName = process.ProcessName,
                                ProcessId = process.ProcessId,
                                Owner = process.Owner,
                                Exploitable = false
                            });
                        }

                        if (HasSuspiciousCommandLine(process))
                        {
                            process.Vulnerabilities.Add(new ProcessVulnerability
                            {
                                Type = "Suspicious Command Line",
                                Severity = "Medium",
                                Description = "Process has suspicious command line arguments",
                                ProcessName = process.ProcessName,
                                ProcessId = process.ProcessId,
                                CommandLine = process.CommandLine,
                                Exploitable = false
                            });
                        }

                        if (IsKnownVulnerableProcess(process))
                        {
                            process.Vulnerabilities.Add(new ProcessVulnerability
                            {
                                Type = "Known Vulnerable Process",
                                Severity = "High",
                                Description = "Process is known to have vulnerabilities",
                                ProcessName = process.ProcessName,
                                ProcessId = process.ProcessId,
                                Exploitable = true
                            });
                        }

                        if (HasNetworkConnections(process))
                        {
                            process.Vulnerabilities.Add(new ProcessVulnerability
                            {
                                Type = "Network Process",
                                Severity = "Low",
                                Description = "Process has network connections",
                                ProcessName = process.ProcessName,
                                ProcessId = process.ProcessId,
                                Exploitable = false
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Process vulnerability analysis failed");
            }
        }

        private async Task AnalyzeProcessPrivileges(List<ProcessInformation> processes)
        {
            try
            {
                await Task.Run(() =>
                {
                    foreach (var process in processes)
                    {
                        process.IsPrivileged = IsPrivilegedProcess(process);
                        process.IsCritical = IsCriticalProcess(process);
                        process.IsSystemProcess = IsSystemProcess(process);
                        process.TrustLevel = DetermineTrustLevel(process);
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Process privilege analysis failed");
            }
        }

        private bool HasUnquotedExecutablePath(ProcessInformation process)
        {
            if (string.IsNullOrEmpty(process.ExecutablePath))
                return false;

            var path = process.ExecutablePath.Trim();
            if (path.StartsWith("\"") && path.EndsWith("\""))
                return false;

            return path.Contains(" ") && !path.StartsWith("C:\\Windows\\System32");
        }

        private bool IsRunningFromTempDirectory(ProcessInformation process)
        {
            if (string.IsNullOrEmpty(process.ExecutablePath))
                return false;

            var suspiciousPaths = new[]
            {
                "\\Temp\\", "\\tmp\\", "\\AppData\\Local\\Temp\\",
                "\\Users\\Public\\", "\\ProgramData\\",
                "C:\\Windows\\Temp\\", "C:\\Temp\\"
            };

            return suspiciousPaths.Any(path =>
                process.ExecutablePath.Contains(path, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsRunningAsSystem(ProcessInformation process)
        {
            if (string.IsNullOrEmpty(process.Owner))
                return false;

            var systemAccounts = new[]
            {
                "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LocalService",
                "NT AUTHORITY\\NetworkService", "SYSTEM"
            };

            return systemAccounts.Any(account =>
                string.Equals(process.Owner, account, StringComparison.OrdinalIgnoreCase));
        }

        private bool HasSuspiciousCommandLine(ProcessInformation process)
        {
            if (string.IsNullOrEmpty(process.CommandLine))
                return false;

            var suspiciousKeywords = new[]
            {
                "powershell", "cmd", "wscript", "cscript", "mshta",
                "rundll32", "regsvr32", "bitsadmin", "certutil"
            };

            return suspiciousKeywords.Any(keyword =>
                process.CommandLine.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsKnownVulnerableProcess(ProcessInformation process)
        {
            var vulnerableProcesses = new[]
            {
                "iexplore", "firefox", "chrome", "java", "javaw",
                "acrobat", "acrord32", "winword", "excel", "powerpnt"
            };

            return vulnerableProcesses.Any(vulnProcess =>
                process.ProcessName.Contains(vulnProcess, StringComparison.OrdinalIgnoreCase));
        }

        private bool HasNetworkConnections(ProcessInformation process)
        {
            var networkProcesses = new[]
            {
                "svchost", "lsass", "services", "winlogon", "csrss",
                "iexplore", "firefox", "chrome", "outlook", "skype"
            };

            return networkProcesses.Any(netProcess =>
                process.ProcessName.Contains(netProcess, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsPrivilegedProcess(ProcessInformation process)
        {
            return IsRunningAsSystem(process) || IsCriticalProcess(process);
        }

        private bool IsCriticalProcess(ProcessInformation process)
        {
            var criticalProcesses = new[]
            {
                "system", "smss", "csrss", "wininit", "winlogon",
                "services", "lsass", "svchost", "spoolsv", "explorer"
            };

            return criticalProcesses.Any(critical =>
                string.Equals(process.ProcessName, critical, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsSystemProcess(ProcessInformation process)
        {
            return process.SessionId == 0 || IsRunningAsSystem(process);
        }

        private string DetermineTrustLevel(ProcessInformation process)
        {
            if (IsCriticalProcess(process)) return "Critical";
            if (IsSystemProcess(process)) return "System";
            if (IsRunningAsSystem(process)) return "Elevated";
            if (IsKnownVulnerableProcess(process)) return "Untrusted";
            return "Standard";
        }

        private void MergeProcessInformation(ProcessInformation target, ProcessInformation source)
        {
            if (string.IsNullOrEmpty(target.CommandLine) && !string.IsNullOrEmpty(source.CommandLine))
                target.CommandLine = source.CommandLine;

            if (string.IsNullOrEmpty(target.Owner) && !string.IsNullOrEmpty(source.Owner))
                target.Owner = source.Owner;

            if (target.ParentProcessId == 0 && source.ParentProcessId != 0)
                target.ParentProcessId = source.ParentProcessId;

            if (string.IsNullOrEmpty(target.Description) && !string.IsNullOrEmpty(source.Description))
                target.Description = source.Description;
        }

        private DateTime GetProcessStartTime(Process process)
        {
            try
            {
                return process.StartTime;
            }
            catch
            {
                return DateTime.MinValue;
            }
        }

        private string GetProcessPriorityClass(Process process)
        {
            try
            {
                return process.PriorityClass.ToString();
            }
            catch
            {
                return "Unknown";
            }
        }

        private bool GetProcessResponding(Process process)
        {
            try
            {
                return process.Responding;
            }
            catch
            {
                return true;
            }
        }

        private string GetProcessExecutablePath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        private string GetProcessOwner(ManagementObject process)
        {
            try
            {
                var owner = new string[2];
                process.InvokeMethod("GetOwner", (object[])owner);
                return $"{owner[1]}\\{owner[0]}";
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}