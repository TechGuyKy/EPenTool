using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.DefenseEvasion
{
    public class DLLHijacking
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<DLLHijacking> _logger;
        private readonly SecurityContext _securityContext;

        public DLLHijacking(IConfiguration configuration, ILogger<DLLHijacking> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<DLLHijackingResult>> ExecuteAsync()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                _logger.LogInformation("Starting DLL hijacking assessment");

                results.AddRange(await CheckDLLSearchOrder());
                results.AddRange(await CheckWritableDirectories());
                results.AddRange(await CheckMissingDLLs());
                results.AddRange(await CheckWOW64Redirection());
                results.AddRange(await CheckDLLSideLoading());
                results.AddRange(await CheckCOMHijacking());
                results.AddRange(await CheckDLLPlantingOpportunities());
                results.AddRange(await CheckKnownVulnerableApplications());

                _logger.LogInformation($"DLL hijacking assessment completed. Found {results.Count} techniques");
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DLL hijacking execution failed");
                results.Add(new DLLHijackingResult
                {
                    TechniqueName = "DLL Hijacking Error",
                    Success = false,
                    Severity = "Error",
                    Description = "DLL hijacking assessment failed",
                    Evidence = ex.Message
                });
                return results;
            }
        }

        private async Task<List<DLLHijackingResult>> CheckDLLSearchOrder()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var searchOrderPaths = GetDLLSearchOrderPaths();

                    results.Add(new DLLHijackingResult
                    {
                        TechniqueName = "DLL Search Order Analysis",
                        Success = true,
                        Severity = "Info",
                        Description = $"Analyzed {searchOrderPaths.Count} search order paths",
                        Evidence = $"Search paths: {string.Join(", ", searchOrderPaths.Take(5))}...",
                        HijackingMethod = "Search Order Hijacking",
                        SearchOrderPaths = searchOrderPaths
                    });

                    for (int i = 0; i < searchOrderPaths.Count && i < 10; i++)
                    {
                        var path = searchOrderPaths[i];
                        if (IsPathWritable(path))
                        {
                            results.Add(new DLLHijackingResult
                            {
                                TechniqueName = "Writable Search Path",
                                Success = true,
                                Severity = "High",
                                Description = $"Writable DLL search path found: {path}",
                                Evidence = $"Path: {path} is writable and in DLL search order (Priority: {i + 1})",
                                HijackingMethod = "Search Order Hijacking",
                                HijackablePath = path,
                                Priority = i + 1
                            });
                        }
                    }

                    CheckCurrentDirectoryHijacking(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check DLL search order");
            }

            return results;
        }

        private async Task<List<DLLHijackingResult>> CheckWritableDirectories()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var systemDirectories = GetSystemDirectories();

                    foreach (var directory in systemDirectories)
                    {
                        if (Directory.Exists(directory))
                        {
                            var writabilityResult = CheckDirectoryWritability(directory);

                            if (writabilityResult.IsWritable)
                            {
                                results.Add(new DLLHijackingResult
                                {
                                    TechniqueName = "Writable System Directory",
                                    Success = true,
                                    Severity = GetSeverityForSystemDirectory(directory),
                                    Description = $"System directory is writable: {Path.GetFileName(directory)}",
                                    Evidence = $"Directory: {directory}, Method: {writabilityResult.Method}",
                                    HijackingMethod = "System Directory Hijacking",
                                    HijackablePath = directory,
                                    WritabilityMethod = writabilityResult.Method
                                });
                            }

                            CheckCommonDLLs(directory, results);
                        }
                    }

                    CheckProgramFilesDLLs(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check writable directories");
            }

            return results;
        }

        private async Task<List<DLLHijackingResult>> CheckMissingDLLs()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var targetApplications = GetTargetApplications();

                    foreach (var app in targetApplications.Take(10))
                    {
                        if (File.Exists(app))
                        {
                            var missingDLLs = FindMissingDLLs(app);

                            foreach (var missingDLL in missingDLLs.Take(5))
                            {
                                var hijackablePaths = FindHijackablePathsForDLL(app, missingDLL);

                                if (hijackablePaths.Any())
                                {
                                    results.Add(new DLLHijackingResult
                                    {
                                        TechniqueName = "Missing DLL Hijacking",
                                        Success = true,
                                        Severity = "High",
                                        Description = $"Missing DLL can be hijacked: {missingDLL}",
                                        Evidence = $"Application: {Path.GetFileName(app)}, Missing DLL: {missingDLL}, Paths: {hijackablePaths.Count}",
                                        HijackingMethod = "Missing DLL Hijacking",
                                        TargetApplication = app,
                                        MissingDLL = missingDLL,
                                        HijackablePaths = hijackablePaths.Take(3).ToList()
                                    });
                                }
                            }
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check missing DLLs");
            }

            return results;
        }

        private async Task<List<DLLHijackingResult>> CheckWOW64Redirection()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    if (Environment.Is64BitOperatingSystem)
                    {
                        var wow64Paths = GetWOW64Paths();

                        foreach (var path in wow64Paths)
                        {
                            if (Directory.Exists(path))
                            {
                                var isWritable = IsPathWritable(path);

                                results.Add(new DLLHijackingResult
                                {
                                    TechniqueName = "WOW64 Redirection Analysis",
                                    Success = isWritable,
                                    Severity = isWritable ? "High" : "Low",
                                    Description = $"WOW64 redirection path: {Path.GetFileName(path)}",
                                    Evidence = $"Path: {path}, Writable: {isWritable}",
                                    HijackingMethod = "WOW64 Redirection",
                                    HijackablePath = isWritable ? path : null,
                                    Architecture = "32-bit on 64-bit"
                                });
                            }
                        }

                        CheckWOW64DLLs(results);
                        CheckWOW64FileSystemRedirection(results);
                    }
                    else
                    {
                        results.Add(new DLLHijackingResult
                        {
                            TechniqueName = "WOW64 Assessment",
                            Success = false,
                            Severity = "Info",
                            Description = "WOW64 redirection not applicable on 32-bit system",
                            Evidence = "System architecture: 32-bit",
                            HijackingMethod = "WOW64 Redirection"
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check WOW64 redirection");
            }

            return results;
        }

        private async Task<List<DLLHijackingResult>> CheckDLLSideLoading()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var sideLoadingTargets = GetSideLoadingTargets();

                    foreach (var target in sideLoadingTargets)
                    {
                        if (File.Exists(target.ExecutablePath))
                        {
                            var sideLoadableDLLs = FindSideLoadableDLLs(target);

                            foreach (var dll in sideLoadableDLLs.Take(3))
                            {
                                results.Add(new DLLHijackingResult
                                {
                                    TechniqueName = "DLL Side-Loading",
                                    Success = true,
                                    Severity = target.IsSigned ? "High" : "Medium",
                                    Description = $"DLL side-loading possible: {dll.DLLName}",
                                    Evidence = $"Target: {target.Name}, DLL: {dll.DLLName}, Signed: {target.IsSigned}",
                                    HijackingMethod = "DLL Side-Loading",
                                    TargetApplication = target.ExecutablePath,
                                    SideLoadableDLL = dll.DLLName,
                                    HijackablePath = dll.LoadPath,
                                    IsSigned = target.IsSigned
                                });
                            }

                            CheckDLLProxying(target, results);
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check DLL side-loading");
            }

            return results;
        }

        private async Task<List<DLLHijackingResult>> CheckCOMHijacking()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var comObjects = GetHijackableCOMObjects();

                    foreach (var comObject in comObjects)
                    {
                        var hijackResult = AnalyzeCOMHijacking(comObject);

                        if (hijackResult.CanHijack)
                        {
                            results.Add(new DLLHijackingResult
                            {
                                TechniqueName = "COM Object Hijacking",
                                Success = true,
                                Severity = hijackResult.Severity,
                                Description = $"COM object can be hijacked: {comObject.Name}",
                                Evidence = $"CLSID: {comObject.CLSID}, Method: {hijackResult.Method}",
                                HijackingMethod = "COM Hijacking",
                                COMObjectName = comObject.Name,
                                CLSID = comObject.CLSID,
                                HijackablePath = hijackResult.HijackPath
                            });
                        }
                    }

                    CheckCOMProxying(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check COM hijacking");
            }

            return results;
        }

        private async Task<List<DLLHijackingResult>> CheckDLLPlantingOpportunities()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var plantingOpportunities = GetDLLPlantingOpportunities();

                    foreach (var opportunity in plantingOpportunities)
                    {
                        if (Directory.Exists(opportunity.Path) && IsPathWritable(opportunity.Path))
                        {
                            results.Add(new DLLHijackingResult
                            {
                                TechniqueName = "DLL Planting Opportunity",
                                Success = true,
                                Severity = opportunity.Severity,
                                Description = $"DLL planting opportunity: {opportunity.Name}",
                                Evidence = $"Location: {opportunity.Path}, Type: {opportunity.Type}",
                                HijackingMethod = "DLL Planting",
                                HijackablePath = opportunity.Path,
                                PlantingType = opportunity.Type
                            });
                        }
                    }

                    CheckTempDirectoryPlanting(results);
                    CheckUserDirectoryPlanting(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check DLL planting opportunities");
            }

            return results;
        }

        private async Task<List<DLLHijackingResult>> CheckKnownVulnerableApplications()
        {
            var results = new List<DLLHijackingResult>();

            try
            {
                await Task.Run(() =>
                {
                    var vulnerableApps = GetKnownVulnerableApplications();

                    foreach (var app in vulnerableApps)
                    {
                        var appPath = FindApplicationPath(app.Name);
                        if (!string.IsNullOrEmpty(appPath) && File.Exists(appPath))
                        {
                            results.Add(new DLLHijackingResult
                            {
                                TechniqueName = "Known Vulnerable Application",
                                Success = true,
                                Severity = "High",
                                Description = $"Known vulnerable application found: {app.Name}",
                                Evidence = $"Application: {app.Name}, Vulnerability: {app.VulnerabilityType}, DLL: {app.VulnerableDLL}",
                                HijackingMethod = "Known Vulnerability",
                                TargetApplication = appPath,
                                VulnerableApplication = app.Name,
                                VulnerabilityType = app.VulnerabilityType,
                                VulnerableDLL = app.VulnerableDLL
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check known vulnerable applications");
            }

            return results;
        }

        private List<string> GetDLLSearchOrderPaths()
        {
            var paths = new List<string>();

            try
            {
                paths.Add(Environment.CurrentDirectory);
                paths.Add(Environment.SystemDirectory);

                var system32 = Environment.SystemDirectory;
                var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

                paths.Add(Path.Combine(systemRoot, "System"));
                paths.Add(systemRoot);

                if (Environment.Is64BitOperatingSystem)
                {
                    paths.Add(Path.Combine(systemRoot, "SysWOW64"));
                }

                var pathEnv = Environment.GetEnvironmentVariable("PATH");
                if (!string.IsNullOrEmpty(pathEnv))
                {
                    var pathDirs = pathEnv.Split(';', StringSplitOptions.RemoveEmptyEntries);
                    paths.AddRange(pathDirs.Where(p => !string.IsNullOrWhiteSpace(p)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get DLL search order paths");
            }

            return paths.Distinct().ToList();
        }

        private void CheckCurrentDirectoryHijacking(List<DLLHijackingResult> results)
        {
            try
            {
                var currentDir = Environment.CurrentDirectory;
                if (IsPathWritable(currentDir))
                {
                    results.Add(new DLLHijackingResult
                    {
                        TechniqueName = "Current Directory Hijacking",
                        Success = true,
                        Severity = "Critical",
                        Description = "Current directory is writable and has highest DLL search priority",
                        Evidence = $"Current directory: {currentDir} (Priority: 1)",
                        HijackingMethod = "Current Directory Hijacking",
                        HijackablePath = currentDir,
                        Priority = 1
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check current directory hijacking");
            }
        }

        private bool IsPathWritable(string path)
        {
            try
            {
                if (!Directory.Exists(path)) return false;

                var testFile = Path.Combine(path, $"test_{Guid.NewGuid():N}.tmp");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private List<string> GetSystemDirectories()
        {
            return new List<string>
            {
                Environment.SystemDirectory,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System"),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Path.Combine(Environment.SystemDirectory, "drivers"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS")
            };
        }

        private (bool IsWritable, string Method) CheckDirectoryWritability(string directory)
        {
            try
            {
                if (IsPathWritable(directory))
                {
                    return (true, "Direct Write");
                }

                var testDir = Path.Combine(directory, $"test_{Guid.NewGuid():N}");
                try
                {
                    Directory.CreateDirectory(testDir);
                    Directory.Delete(testDir);
                    return (true, "Subdirectory Creation");
                }
                catch
                {
                    return (false, "No Write Access");
                }
            }
            catch
            {
                return (false, "No Write Access");
            }
        }

        private string GetSeverityForSystemDirectory(string directory)
        {
            var dirName = Path.GetFileName(directory).ToLower();
            return dirName switch
            {
                "system32" => "Critical",
                "syswow64" => "Critical",
                "system" => "Critical",
                "windows" => "High",
                "drivers" => "Critical",
                _ => "Medium"
            };
        }

        private void CheckCommonDLLs(string directory, List<DLLHijackingResult> results)
        {
            try
            {
                var commonDLLs = new[]
                {
                    "version.dll", "dwmapi.dll", "uxtheme.dll", "winmm.dll",
                    "dbghelp.dll", "iphlpapi.dll", "winhttp.dll", "crypt32.dll",
                    "wtsapi32.dll", "propsys.dll"
                };

                foreach (var dll in commonDLLs.Take(5))
                {
                    var dllPath = Path.Combine(directory, dll);
                    if (!File.Exists(dllPath) && IsPathWritable(directory))
                    {
                        results.Add(new DLLHijackingResult
                        {
                            TechniqueName = "Missing Common DLL",
                            Success = true,
                            Severity = "High",
                            Description = $"Common DLL missing and path writable: {dll}",
                            Evidence = $"Directory: {Path.GetFileName(directory)}, Missing DLL: {dll}",
                            HijackingMethod = "Missing DLL Hijacking",
                            HijackablePath = dllPath,
                            MissingDLL = dll
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check common DLLs in: {directory}");
            }
        }

        private void CheckProgramFilesDLLs(List<DLLHijackingResult> results)
        {
            try
            {
                var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (Directory.Exists(programFiles))
                {
                    var directories = Directory.GetDirectories(programFiles).Take(5);

                    foreach (var dir in directories)
                    {
                        if (IsPathWritable(dir))
                        {
                            results.Add(new DLLHijackingResult
                            {
                                TechniqueName = "Writable Program Files Directory",
                                Success = true,
                                Severity = "High",
                                Description = $"Writable Program Files subdirectory: {Path.GetFileName(dir)}",
                                Evidence = $"Directory: {dir}",
                                HijackingMethod = "Program Files Hijacking",
                                HijackablePath = dir
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check Program Files DLLs");
            }
        }

        private List<string> GetTargetApplications()
        {
            var applications = new List<string>();

            try
            {
                var commonApps = new[]
                {
                    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
                    "explorer.exe", "cmd.exe", "powershell.exe", "winver.exe"
                };

                foreach (var app in commonApps)
                {
                    var systemPath = Path.Combine(Environment.SystemDirectory, app);
                    if (File.Exists(systemPath))
                        applications.Add(systemPath);
                }

                var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (Directory.Exists(programFiles))
                {
                    var subDirs = Directory.GetDirectories(programFiles).Take(3);
                    foreach (var dir in subDirs)
                    {
                        try
                        {
                            var exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly).Take(2);
                            applications.AddRange(exeFiles);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, $"Failed to scan directory: {dir}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get target applications");
            }

            return applications;
        }

        private List<string> FindMissingDLLs(string applicationPath)
        {
            var missingDLLs = new List<string>();

            try
            {
                var commonDLLs = new[]
                {
                    "version.dll", "dwmapi.dll", "uxtheme.dll", "winmm.dll",
                    "dbghelp.dll", "iphlpapi.dll", "winhttp.dll", "crypt32.dll",
                    "wtsapi32.dll", "propsys.dll", "netapi32.dll", "userenv.dll"
                };

                var appDirectory = Path.GetDirectoryName(applicationPath);
                if (appDirectory != null)
                {
                    foreach (var dll in commonDLLs)
                    {
                        var dllPath = Path.Combine(appDirectory, dll);
                        if (!File.Exists(dllPath))
                        {
                            missingDLLs.Add(dll);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to find missing DLLs for: {applicationPath}");
            }

            return missingDLLs;
        }

        private List<string> FindHijackablePathsForDLL(string applicationPath, string dllName)
        {
            var hijackablePaths = new List<string>();

            try
            {
                var appDirectory = Path.GetDirectoryName(applicationPath);
                if (appDirectory != null && IsPathWritable(appDirectory))
                {
                    hijackablePaths.Add(Path.Combine(appDirectory, dllName));
                }

                var searchPaths = GetDLLSearchOrderPaths();
                foreach (var path in searchPaths.Take(5))
                {
                    if (IsPathWritable(path))
                    {
                        hijackablePaths.Add(Path.Combine(path, dllName));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to find hijackable paths for DLL: {dllName}");
            }

            return hijackablePaths;
        }

        private List<string> GetWOW64Paths()
        {
            var paths = new List<string>();

            try
            {
                var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                paths.Add(Path.Combine(windowsDir, "SysWOW64"));

                var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                if (!string.IsNullOrEmpty(programFilesX86))
                {
                    paths.Add(programFilesX86);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get WOW64 paths");
            }

            return paths.Where(p => !string.IsNullOrEmpty(p)).ToList();
        }

        private void CheckWOW64DLLs(List<DLLHijackingResult> results)
        {
            try
            {
                var wow64Dlls = new[] { "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll" };
                var sysWow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

                if (Directory.Exists(sysWow64))
                {
                    foreach (var dll in wow64Dlls.Take(3))
                    {
                        var dllPath = Path.Combine(sysWow64, dll);
                        if (File.Exists(dllPath))
                        {
                            results.Add(new DLLHijackingResult
                            {
                                TechniqueName = "WOW64 DLL Analysis",
                                Success = true,
                                Severity = "Info",
                                Description = $"WOW64 DLL present: {dll}",
                                Evidence = $"32-bit DLL: {Path.GetFileName(dllPath)}",
                                HijackingMethod = "WOW64 Analysis",
                                Architecture = "32-bit",
                                HijackablePath = sysWow64
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check WOW64 DLLs");
            }
        }

        private void CheckWOW64FileSystemRedirection(List<DLLHijackingResult> results)
        {
            try
            {
                results.Add(new DLLHijackingResult
                {
                    TechniqueName = "WOW64 File System Redirection",
                    Success = true,
                    Severity = "Medium",
                    Description = "WOW64 file system redirection can be exploited",
                    Evidence = "32-bit applications redirected to SysWOW64",
                    HijackingMethod = "WOW64 Redirection",
                    Architecture = "32-bit on 64-bit"
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check WOW64 file system redirection");
            }
        }

        private List<SideLoadingTarget> GetSideLoadingTargets()
        {
            return new List<SideLoadingTarget>
            {
                new SideLoadingTarget { Name = "Notepad", ExecutablePath = Path.Combine(Environment.SystemDirectory, "notepad.exe"), IsSigned = true },
                new SideLoadingTarget { Name = "Calculator", ExecutablePath = Path.Combine(Environment.SystemDirectory, "calc.exe"), IsSigned = true },
                new SideLoadingTarget { Name = "Paint", ExecutablePath = Path.Combine(Environment.SystemDirectory, "mspaint.exe"), IsSigned = true },
                new SideLoadingTarget { Name = "WordPad", ExecutablePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows NT", "Accessories", "wordpad.exe"), IsSigned = true }
            };
        }

        private List<SideLoadableDLL> FindSideLoadableDLLs(SideLoadingTarget target)
        {
            var sideLoadableDLLs = new List<SideLoadableDLL>();

            try
            {
                var appDirectory = Path.GetDirectoryName(target.ExecutablePath);
                var commonSideLoadDLLs = new[]
                {
                    "version.dll", "dwmapi.dll", "winmm.dll", "uxtheme.dll",
                    "dbghelp.dll", "wtsapi32.dll", "propsys.dll"
                };

                if (appDirectory != null)
                {
                    foreach (var dll in commonSideLoadDLLs.Take(4))
                    {
                        var dllPath = Path.Combine(appDirectory, dll);
                        if (!File.Exists(dllPath) && IsPathWritable(appDirectory))
                        {
                            sideLoadableDLLs.Add(new SideLoadableDLL
                            {
                                DLLName = dll,
                                LoadPath = dllPath
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to find side-loadable DLLs for: {target.Name}");
            }

            return sideLoadableDLLs;
        }

        private void CheckDLLProxying(SideLoadingTarget target, List<DLLHijackingResult> results)
        {
            try
            {
                var proxyMethods = new[] { "Export Forwarding", "DLL Redirection", "Phantom DLL Loading" };

                foreach (var method in proxyMethods.Take(2))
                {
                    results.Add(new DLLHijackingResult
                    {
                        TechniqueName = "DLL Proxying Method",
                        Success = true,
                        Severity = "Medium",
                        Description = $"DLL proxying technique available: {method}",
                        Evidence = $"Target: {target.Name}, Method: {method}",
                        HijackingMethod = "DLL Proxying",
                        TargetApplication = target.ExecutablePath,
                        ProxyMethod = method
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check DLL proxying for: {target.Name}");
            }
        }

        private List<COMObject> GetHijackableCOMObjects()
        {
            return new List<COMObject>
            {
                new COMObject { Name = "Shell.Application", CLSID = "{13709620-C279-11CE-A49E-444553540000}", DLLPath = "shell32.dll" },
                new COMObject { Name = "WScript.Shell", CLSID = "{72C24DD5-D70A-438B-8A42-98424B88AFB8}", DLLPath = "wshom.ocx" },
                new COMObject { Name = "Scripting.FileSystemObject", CLSID = "{0D43FE01-F093-11CF-8940-00A0C9054228}", DLLPath = "scrrun.dll" },
                new COMObject { Name = "InternetExplorer.Application", CLSID = "{0002DF01-0000-0000-C000-000000000046}", DLLPath = "ieframe.dll" }
            };
        }

        private COMHijackingResult AnalyzeCOMHijacking(COMObject comObject)
        {
            try
            {
                using var hkcr = Microsoft.Win32.Registry.ClassesRoot;

                // Check HKCR hijacking
                using var clsidKey = hkcr.OpenSubKey($@"CLSID\{comObject.CLSID}", true);
                if (clsidKey != null)
                {
                    return new COMHijackingResult
                    {
                        CanHijack = true,
                        Method = "HKCR Registry Hijacking",
                        Severity = "High",
                        HijackPath = $@"HKCR\CLSID\{comObject.CLSID}"
                    };
                }

                // Check HKCU hijacking possibility
                using var hkcu = Microsoft.Win32.Registry.CurrentUser;
                try
                {
                    using var userClsidKey = hkcu.CreateSubKey($@"Software\Classes\CLSID\{comObject.CLSID}");
                    if (userClsidKey != null)
                    {
                        return new COMHijackingResult
                        {
                            CanHijack = true,
                            Method = "HKCU Registry Hijacking",
                            Severity = "Medium",
                            HijackPath = $@"HKCU\Software\Classes\CLSID\{comObject.CLSID}"
                        };
                    }
                }
                catch
                {
                    // HKCU creation failed
                }

                return new COMHijackingResult { CanHijack = false };
            }
            catch
            {
                return new COMHijackingResult { CanHijack = false };
            }
        }

        private void CheckCOMProxying(List<DLLHijackingResult> results)
        {
            try
            {
                results.Add(new DLLHijackingResult
                {
                    TechniqueName = "COM DLL Proxying",
                    Success = true,
                    Severity = "Medium",
                    Description = "COM DLL proxying techniques available",
                    Evidence = "COM objects can be hijacked through registry manipulation",
                    HijackingMethod = "COM Proxying"
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check COM proxying");
            }
        }

        private List<DLLPlantingOpportunity> GetDLLPlantingOpportunities()
        {
            return new List<DLLPlantingOpportunity>
            {
                new DLLPlantingOpportunity { Name = "Temp Directory", Path = Path.GetTempPath(), Type = "Temporary Files", Severity = "Medium" },
                new DLLPlantingOpportunity { Name = "User Desktop", Path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop), Type = "User Directory", Severity = "Low" },
                new DLLPlantingOpportunity { Name = "Downloads Folder", Path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads", Type = "User Directory", Severity = "Low" },
                new DLLPlantingOpportunity { Name = "Public Documents", Path = Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), Type = "Shared Directory", Severity = "Medium" }
            };
        }

        private void CheckTempDirectoryPlanting(List<DLLHijackingResult> results)
        {
            try
            {
                var tempPath = Path.GetTempPath();
                if (IsPathWritable(tempPath))
                {
                    results.Add(new DLLHijackingResult
                    {
                        TechniqueName = "Temp Directory DLL Planting",
                        Success = true,
                        Severity = "Medium",
                        Description = "Temporary directory is writable for DLL planting",
                        Evidence = $"Temp path: {tempPath}",
                        HijackingMethod = "DLL Planting",
                        HijackablePath = tempPath,
                        PlantingType = "Temporary Files"
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check temp directory planting");
            }
        }

        private void CheckUserDirectoryPlanting(List<DLLHijackingResult> results)
        {
            try
            {
                var userDirs = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };

                foreach (var dir in userDirs.Take(2))
                {
                    if (Directory.Exists(dir) && IsPathWritable(dir))
                    {
                        results.Add(new DLLHijackingResult
                        {
                            TechniqueName = "User Directory DLL Planting",
                            Success = true,
                            Severity = "Low",
                            Description = $"User directory is writable: {Path.GetFileName(dir)}",
                            Evidence = $"Directory: {dir}",
                            HijackingMethod = "DLL Planting",
                            HijackablePath = dir,
                            PlantingType = "User Directory"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check user directory planting");
            }
        }

        private List<KnownVulnerableApp> GetKnownVulnerableApplications()
        {
            return new List<KnownVulnerableApp>
            {
                new KnownVulnerableApp { Name = "Notepad++", VulnerabilityType = "DLL Side-Loading", VulnerableDLL = "version.dll" },
                new KnownVulnerableApp { Name = "7-Zip", VulnerabilityType = "Missing DLL", VulnerableDLL = "msvcp140.dll" },
                new KnownVulnerableApp { Name = "VLC Media Player", VulnerabilityType = "DLL Hijacking", VulnerableDLL = "libvlc.dll" },
                new KnownVulnerableApp { Name = "Adobe Reader", VulnerabilityType = "DLL Side-Loading", VulnerableDLL = "version.dll" }
            };
        }

        private string FindApplicationPath(string appName)
        {
            try
            {
                var searchPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) ?? string.Empty,
                    Environment.SystemDirectory
                }.Where(p => !string.IsNullOrEmpty(p));

                foreach (var basePath in searchPaths)
                {
                    if (Directory.Exists(basePath))
                    {
                        var foundDirs = Directory.GetDirectories(basePath, $"*{appName}*", SearchOption.TopDirectoryOnly);
                        foreach (var dir in foundDirs.Take(1))
                        {
                            var exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                            if (exeFiles.Length > 0)
                            {
                                return exeFiles[0];
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to find application path for: {appName}");
            }

            return string.Empty;
        }

        private class SideLoadingTarget
        {
            public string Name { get; set; } = string.Empty;
            public string ExecutablePath { get; set; } = string.Empty;
            public bool IsSigned { get; set; }
        }

        private class SideLoadableDLL
        {
            public string DLLName { get; set; } = string.Empty;
            public string LoadPath { get; set; } = string.Empty;
        }

        private class COMObject
        {
            public string Name { get; set; } = string.Empty;
            public string CLSID { get; set; } = string.Empty;
            public string DLLPath { get; set; } = string.Empty;
        }

        private class COMHijackingResult
        {
            public bool CanHijack { get; set; }
            public string Method { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
            public string HijackPath { get; set; } = string.Empty;
        }

        private class DLLPlantingOpportunity
        {
            public string Name { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
            public string Type { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
        }

        private class KnownVulnerableApp
        {
            public string Name { get; set; } = string.Empty;
            public string VulnerabilityType { get; set; } = string.Empty;
            public string VulnerableDLL { get; set; } = string.Empty;
        }
    }
}