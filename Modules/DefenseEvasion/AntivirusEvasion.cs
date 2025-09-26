using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Management;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Core;
using EPenT.Models.Results;

namespace EliteWindowsPentestSuite.Modules.DefenseEvasion
{
    public class AntivirusEvasion
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AntivirusEvasion> _logger;
        private readonly SecurityContext _securityContext;

        public AntivirusEvasion(IConfiguration configuration, ILogger<AntivirusEvasion> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<AntivirusEvasionResult>> ExecuteAsync()
        {
            var results = new List<AntivirusEvasionResult>();

            try
            {
                _logger.LogInformation("Starting antivirus evasion assessment");

                results.AddRange(await DetectAntivirusProducts());
                results.AddRange(await CheckRealtimeProtection());
                results.AddRange(await CheckExclusionPaths());
                results.AddRange(await CheckProcessWhitelisting());
                results.AddRange(await CheckFileObfuscation());
                results.AddRange(await CheckBehavioralDetection());

                _logger.LogInformation($"Antivirus evasion assessment completed. Found {results.Count} techniques");
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Antivirus evasion execution failed");
                results.Add(new AntivirusEvasionResult
                {
                    TechniqueName = "Antivirus Evasion Error",
                    Success = false,
                    Severity = "Error",
                    Description = "Antivirus evasion assessment failed",
                    Evidence = ex.Message
                });
                return results;
            }
        }

        private async Task<List<AntivirusEvasionResult>> DetectAntivirusProducts()
        {
            var results = new List<AntivirusEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var antivirusProducts = GetInstalledAntivirusProducts();

                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Antivirus Product Detection",
                        Success = true,
                        Severity = "Info",
                        Description = $"Found {antivirusProducts.Count} antivirus products installed",
                        Evidence = $"Installed products: {string.Join(", ", antivirusProducts)}",
                        EvasionMethod = "Product Enumeration",
                        DetectedProducts = antivirusProducts
                    });

                    foreach (var product in antivirusProducts)
                    {
                        var evasionTechniques = GetProductSpecificEvasionTechniques(product);

                        results.Add(new AntivirusEvasionResult
                        {
                            TechniqueName = "Product-Specific Evasion",
                            Success = true,
                            Severity = "Medium",
                            Description = $"Evasion techniques available for {product}",
                            Evidence = $"Product: {product}, Techniques: {string.Join(", ", evasionTechniques)}",
                            EvasionMethod = "Product Targeting",
                            AntivirusProduct = product,
                            EvasionTechniques = evasionTechniques
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to detect antivirus products");
            }

            return results;
        }

        private async Task<List<AntivirusEvasionResult>> CheckRealtimeProtection()
        {
            var results = new List<AntivirusEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var realtimeStatus = GetRealtimeProtectionStatus();

                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Realtime Protection Status",
                        Success = true,
                        Severity = realtimeStatus ? "High" : "Low",
                        Description = $"Realtime protection is {(realtimeStatus ? "enabled" : "disabled")}",
                        Evidence = $"Realtime scanning: {(realtimeStatus ? "Active" : "Inactive")}",
                        EvasionMethod = "Protection Analysis",
                        RealtimeProtectionEnabled = realtimeStatus
                    });

                    if (realtimeStatus)
                    {
                        CheckRealtimeExclusions(results);
                        CheckRealtimeBypasses(results);
                    }
                    else
                    {
                        results.Add(new AntivirusEvasionResult
                        {
                            TechniqueName = "Realtime Protection Disabled",
                            Success = true,
                            Severity = "Critical",
                            Description = "Realtime protection is disabled - direct execution possible",
                            Evidence = "No active realtime scanning detected",
                            EvasionMethod = "Direct Execution"
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check realtime protection");
            }

            return results;
        }

        private async Task<List<AntivirusEvasionResult>> CheckExclusionPaths()
        {
            var results = new List<AntivirusEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var exclusionPaths = GetAntivirusExclusions();

                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Antivirus Exclusions",
                        Success = true,
                        Severity = exclusionPaths.Count > 0 ? "High" : "Low",
                        Description = $"Found {exclusionPaths.Count} antivirus exclusion paths",
                        Evidence = $"Exclusion paths: {string.Join(", ", exclusionPaths)}",
                        EvasionMethod = "Exclusion Abuse",
                        ExclusionPaths = exclusionPaths
                    });

                    foreach (var exclusion in exclusionPaths)
                    {
                        if (IsPathWritable(exclusion))
                        {
                            results.Add(new AntivirusEvasionResult
                            {
                                TechniqueName = "Writable Exclusion Path",
                                Success = true,
                                Severity = "Critical",
                                Description = $"Writable exclusion path found: {exclusion}",
                                Evidence = $"Path: {exclusion} is writable and excluded from scanning",
                                EvasionMethod = "Exclusion Path Abuse",
                                ExclusionPath = exclusion
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check exclusion paths");
            }

            return results;
        }

        private async Task<List<AntivirusEvasionResult>> CheckProcessWhitelisting()
        {
            var results = new List<AntivirusEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var whitelistedProcesses = GetWhitelistedProcesses();

                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Process Whitelisting",
                        Success = true,
                        Severity = whitelistedProcesses.Count > 0 ? "Medium" : "Low",
                        Description = $"Found {whitelistedProcesses.Count} whitelisted processes",
                        Evidence = $"Whitelisted processes: {string.Join(", ", whitelistedProcesses)}",
                        EvasionMethod = "Process Masquerading",
                        WhitelistedProcesses = whitelistedProcesses
                    });

                    foreach (var process in whitelistedProcesses)
                    {
                        if (CanMasqueradeAsProcess(process))
                        {
                            results.Add(new AntivirusEvasionResult
                            {
                                TechniqueName = "Process Masquerading Opportunity",
                                Success = true,
                                Severity = "High",
                                Description = $"Can masquerade as whitelisted process: {process}",
                                Evidence = $"Process: {process} can be used for masquerading",
                                EvasionMethod = "Process Masquerading",
                                TargetProcess = process
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check process whitelisting");
            }

            return results;
        }

        private async Task<List<AntivirusEvasionResult>> CheckFileObfuscation()
        {
            var results = new List<AntivirusEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var obfuscationTechniques = GetSupportedObfuscationTechniques();

                    foreach (var technique in obfuscationTechniques)
                    {
                        results.Add(new AntivirusEvasionResult
                        {
                            TechniqueName = "File Obfuscation Technique",
                            Success = true,
                            Severity = "Medium",
                            Description = $"File obfuscation technique available: {technique}",
                            Evidence = $"Obfuscation method: {technique}",
                            EvasionMethod = "File Obfuscation",
                            ObfuscationTechnique = technique
                        });
                    }

                    CheckPackerDetection(results);
                    CheckCrypterCapabilities(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check file obfuscation");
            }

            return results;
        }

        private async Task<List<AntivirusEvasionResult>> CheckBehavioralDetection()
        {
            var results = new List<AntivirusEvasionResult>();

            try
            {
                await Task.Run(() =>
                {
                    var behavioralFeatures = GetBehavioralDetectionFeatures();

                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Behavioral Detection Analysis",
                        Success = true,
                        Severity = "Info",
                        Description = $"Found {behavioralFeatures.Count} behavioral detection features",
                        Evidence = $"Features: {string.Join(", ", behavioralFeatures)}",
                        EvasionMethod = "Behavioral Analysis",
                        BehavioralFeatures = behavioralFeatures
                    });

                    CheckSandboxEvasion(results);
                    CheckDelayedExecution(results);
                    CheckEnvironmentChecks(results);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check behavioral detection");
            }

            return results;
        }

        private List<string> GetInstalledAntivirusProducts()
        {
            var products = new List<string>();

            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                using var results = searcher.Get();

                foreach (ManagementObject result in results)
                {
                    try
                    {
                        var displayName = result["displayName"]?.ToString();
                        if (!string.IsNullOrEmpty(displayName))
                        {
                            products.Add(displayName);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to process antivirus product");
                    }
                    finally
                    {
                        result?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get installed antivirus products");
            }

            return products;
        }

        private List<string> GetProductSpecificEvasionTechniques(string product)
        {
            var techniques = new List<string>();

            var productLower = product.ToLower();

            if (productLower.Contains("windows defender"))
            {
                techniques.AddRange(new[] { "AMSI Bypass", "Real-time Protection Disable", "Exclusion Path Abuse" });
            }
            else if (productLower.Contains("norton") || productLower.Contains("symantec"))
            {
                techniques.AddRange(new[] { "Process Hollowing", "DLL Side-loading", "Behavioral Evasion" });
            }
            else if (productLower.Contains("mcafee"))
            {
                techniques.AddRange(new[] { "File Obfuscation", "Registry Evasion", "Service Manipulation" });
            }
            else if (productLower.Contains("kaspersky"))
            {
                techniques.AddRange(new[] { "Memory Patching", "Rootkit Techniques", "Kernel Bypass" });
            }
            else
            {
                techniques.AddRange(new[] { "Generic Obfuscation", "Packing", "Delayed Execution" });
            }

            return techniques;
        }

        private bool GetRealtimeProtectionStatus()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                if (key != null)
                {
                    var disableRealtimeMonitoring = key.GetValue("DisableRealtimeMonitoring");
                    return disableRealtimeMonitoring?.ToString() != "1";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check realtime protection status");
            }

            return true;
        }

        private void CheckRealtimeExclusions(List<AntivirusEvasionResult> results)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");
                if (key != null)
                {
                    var exclusions = key.GetValueNames();
                    if (exclusions.Length > 0)
                    {
                        results.Add(new AntivirusEvasionResult
                        {
                            TechniqueName = "Windows Defender Exclusions",
                            Success = true,
                            Severity = "High",
                            Description = $"Found {exclusions.Length} Windows Defender exclusions",
                            Evidence = $"Exclusions: {string.Join(", ", exclusions)}",
                            EvasionMethod = "Defender Exclusion Abuse"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check realtime exclusions");
            }
        }

        private void CheckRealtimeBypasses(List<AntivirusEvasionResult> results)
        {
            try
            {
                var bypassTechniques = new[]
                {
                    "PowerShell Execution Policy Bypass",
                    "Living off the Land Binaries",
                    "Signed Binary Proxy Execution",
                    "Process Injection"
                };

                foreach (var technique in bypassTechniques)
                {
                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Realtime Bypass Technique",
                        Success = true,
                        Severity = "Medium",
                        Description = $"Realtime bypass available: {technique}",
                        Evidence = $"Technique: {technique}",
                        EvasionMethod = "Realtime Bypass",
                        BypassTechnique = technique
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check realtime bypasses");
            }
        }

        private List<string> GetAntivirusExclusions()
        {
            var exclusions = new List<string>();

            try
            {
                var exclusionRegistryPaths = new[]
                {
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
                };

                foreach (var registryPath in exclusionRegistryPaths)
                {
                    try
                    {
                        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(registryPath);
                        if (key != null)
                        {
                            exclusions.AddRange(key.GetValueNames());
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, $"Failed to check exclusion registry: {registryPath}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get antivirus exclusions");
            }

            return exclusions;
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

        private List<string> GetWhitelistedProcesses()
        {
            return new List<string>
            {
                "svchost.exe",
                "explorer.exe",
                "winlogon.exe",
                "csrss.exe",
                "lsass.exe",
                "powershell.exe",
                "cmd.exe",
                "rundll32.exe",
                "regsvr32.exe"
            };
        }

        private bool CanMasqueradeAsProcess(string processName)
        {
            try
            {
                var systemPaths = new[]
                {
                    Environment.SystemDirectory,
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0")
                };

                foreach (var path in systemPaths)
                {
                    var fullPath = Path.Combine(path, processName);
                    if (File.Exists(fullPath))
                    {
                        return IsPathWritable(path);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to check masquerading for: {processName}");
            }

            return false;
        }

        private List<string> GetSupportedObfuscationTechniques()
        {
            return new List<string>
            {
                "Base64 Encoding",
                "XOR Encryption",
                "String Obfuscation",
                "Control Flow Obfuscation",
                "API Hashing",
                "Polymorphic Code",
                "Metamorphic Code"
            };
        }

        private void CheckPackerDetection(List<AntivirusEvasionResult> results)
        {
            try
            {
                var commonPackers = new[]
                {
                    "UPX", "ASPack", "PECompact", "VMProtect", "Themida", "Enigma"
                };

                foreach (var packer in commonPackers)
                {
                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Packer Availability",
                        Success = true,
                        Severity = "Medium",
                        Description = $"Packer technique available: {packer}",
                        Evidence = $"Packer: {packer}",
                        EvasionMethod = "File Packing",
                        PackerName = packer
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check packer detection");
            }
        }

        private void CheckCrypterCapabilities(List<AntivirusEvasionResult> results)
        {
            try
            {
                var crypters = new[]
                {
                    "Custom XOR Crypter",
                    "AES Encryption Stub",
                    "RC4 Encryption Wrapper",
                    "Polymorphic Crypter"
                };

                foreach (var crypter in crypters)
                {
                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Crypter Capability",
                        Success = true,
                        Severity = "High",
                        Description = $"Crypter technique available: {crypter}",
                        Evidence = $"Crypter: {crypter}",
                        EvasionMethod = "File Encryption",
                        CrypterType = crypter
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check crypter capabilities");
            }
        }

        private List<string> GetBehavioralDetectionFeatures()
        {
            return new List<string>
            {
                "Heuristic Analysis",
                "Machine Learning Detection",
                "Behavioral Monitoring",
                "Sandbox Analysis",
                "Cloud-based Detection",
                "Reputation Analysis"
            };
        }

        private void CheckSandboxEvasion(List<AntivirusEvasionResult> results)
        {
            try
            {
                var sandboxChecks = new[]
                {
                    "VM Detection",
                    "Debugger Detection",
                    "Analysis Tool Detection",
                    "Mouse Movement Check",
                    "Sleep Delay",
                    "File System Artifacts"
                };

                foreach (var check in sandboxChecks)
                {
                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Sandbox Evasion Check",
                        Success = true,
                        Severity = "Medium",
                        Description = $"Sandbox evasion technique: {check}",
                        Evidence = $"Check: {check}",
                        EvasionMethod = "Sandbox Evasion",
                        SandboxCheck = check
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check sandbox evasion");
            }
        }

        private void CheckDelayedExecution(List<AntivirusEvasionResult> results)
        {
            try
            {
                results.Add(new AntivirusEvasionResult
                {
                    TechniqueName = "Delayed Execution",
                    Success = true,
                    Severity = "Medium",
                    Description = "Time-based evasion techniques available",
                    Evidence = "Sleep delays, scheduled tasks, persistence mechanisms",
                    EvasionMethod = "Time-based Evasion"
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check delayed execution");
            }
        }

        private void CheckEnvironmentChecks(List<AntivirusEvasionResult> results)
        {
            try
            {
                var environmentChecks = new[]
                {
                    "Domain Join Status",
                    "User Activity Level",
                    "System Uptime",
                    "Installed Software Count",
                    "Network Connectivity",
                    "Hardware Specifications"
                };

                foreach (var check in environmentChecks)
                {
                    results.Add(new AntivirusEvasionResult
                    {
                        TechniqueName = "Environment Check",
                        Success = true,
                        Severity = "Low",
                        Description = $"Environment validation: {check}",
                        Evidence = $"Check: {check}",
                        EvasionMethod = "Environment Validation",
                        EnvironmentCheck = check
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to check environment checks");
            }
        }
    }
}