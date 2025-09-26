using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Models.Results;
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
                        Evidence = $"Search paths: {string.Join(", ", searchOrderPaths)}",
                        HijackingMethod = "Search Order Hijacking",
                        SearchOrderPaths = searchOrderPaths
                    });

                    foreach (var path in searchOrderPaths)
                    {
                        if (IsPathWritable(path))
                        {
                            results.Add(new DLLHijackingResult
                            {
                                TechniqueName = "Writable Search Path",
                                Success = true,
                                Severity = "High",
                                Description = $"Writable DLL search path found: {path}",
                                Evidence = $"Path: {path} is writable and in DLL search order",
                                HijackingMethod = "Search Order Hijacking",
                                HijackablePath = path,
                                Priority = GetSearchOrderPriority(path)
                            });
                        }
                    }
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
                                    Severity = "Critical",
                                    Description = $"System directory is writable: {directory}",
                                    Evidence = $"Directory: {directory}, Method: {writabilityResult.Method}",
                                    HijackingMethod = "System Directory Hijacking",
                                    HijackablePath = directory,
                                    WritabilityMethod = writabilityResult.Method
                                });
                            }

                            CheckCommonDLLs(directory, results);
                        }
                    }
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

                    foreach (var app in targetApplications)
                    {
                        if (File.Exists(app))
                        {
                            var missingDLLs = FindMissingDLLs(app);

                            foreach (var missingDLL in missingDLLs)
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
                                        Evidence = $"Application: {app}, Missing DLL: {missingDLL}, Paths: {string.Join(", ", hijackablePaths)}",
                                        HijackingMethod = "Missing DLL Hijacking",
                                        TargetApplication = app,
                                        MissingDLL = missingDLL,
                                        HijackablePaths = hijackablePaths
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
                            if (Directory.Exists(path) && IsPathWritable(path))
                            {
                                results.Add(new DLLHijackingResult
                                {
                                    TechniqueName = "WOW64 Redirection Hijacking",
                                    Success = true,
                                    Severity = "High",
                                    Description = $"WOW64 redirection path is writable: {path}",
                                    Evidence = $"WOW64 path: {path} allows DLL placement",
                                    HijackingMethod = "WOW64 Redirection",
                                    HijackablePath = path,
                                    Architecture = "32-bit on 64-bit"
                                });
                            }
                        }

                        CheckWOW64DLLs(results);
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
        }
    }
}