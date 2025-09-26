using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.ServiceProcess;
using System.Management;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Models.System;
using EPenT.Models.Vulnerabilities;

namespace EPenT.Modules.Reconnaissance
{
    public class ServiceEnumerator
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ServiceEnumerator> _logger;

        public ServiceEnumerator(IConfiguration configuration, ILogger<ServiceEnumerator> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<List<ServiceInformation>> EnumerateServicesAsync()
        {
            var services = new List<ServiceInformation>();

            try
            {
                _logger.LogInformation("Starting service enumeration");

                var systemServices = await GetSystemServicesAsync();
                var wmiServices = await GetWMIServicesAsync();

                services.AddRange(systemServices);

                foreach (var wmiService in wmiServices)
                {
                    if (!services.Any(s => string.Equals(s.ServiceName, wmiService.ServiceName, StringComparison.OrdinalIgnoreCase)))
                    {
                        services.Add(wmiService);
                    }
                }

                await AnalyzeServiceVulnerabilities(services);

                _logger.LogInformation($"Service enumeration completed. Found {services.Count} services");
                return services.OrderBy(s => s.ServiceName).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service enumeration failed");
                return services;
            }
        }

        private async Task<List<ServiceInformation>> GetSystemServicesAsync()
        {
            var services = new List<ServiceInformation>();

            try
            {
                await Task.Run(() =>
                {
                    var systemServices = ServiceController.GetServices();

                    foreach (var service in systemServices)
                    {
                        try
                        {
                            var serviceInfo = new ServiceInformation
                            {
                                ServiceName = service.ServiceName,
                                DisplayName = service.DisplayName,
                                Status = service.Status.ToString(),
                                StartType = GetServiceStartType(service.ServiceName),
                                ServiceType = service.ServiceType.ToString(),
                                CanStop = service.CanStop,
                                CanPauseAndContinue = service.CanPauseAndContinue,
                                ExecutablePath = GetServiceExecutablePath(service.ServiceName),
                                Description = GetServiceDescription(service.ServiceName),
                                Account = GetServiceAccount(service.ServiceName)
                            };

                            services.Add(serviceInfo);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, $"Failed to get details for service: {service.ServiceName}");
                        }
                        finally
                        {
                            service?.Dispose();
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate system services");
            }

            return services;
        }

        private async Task<List<ServiceInformation>> GetWMIServicesAsync()
        {
            var services = new List<ServiceInformation>();

            try
            {
                await Task.Run(() =>
                {
                    using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
                    using var results = searcher.Get();

                    foreach (ManagementObject service in results)
                    {
                        try
                        {
                            var serviceInfo = new ServiceInformation
                            {
                                ServiceName = service["Name"]?.ToString() ?? "Unknown",
                                DisplayName = service["DisplayName"]?.ToString() ?? "Unknown",
                                Status = service["State"]?.ToString() ?? "Unknown",
                                StartType = service["StartMode"]?.ToString() ?? "Unknown",
                                ExecutablePath = service["PathName"]?.ToString() ?? "Unknown",
                                Description = service["Description"]?.ToString() ?? "No description",
                                Account = service["StartName"]?.ToString() ?? "Unknown",
                                ProcessId = Convert.ToInt32(service["ProcessId"] ?? 0),
                                ServiceType = service["ServiceType"]?.ToString() ?? "Unknown",
                                ErrorControl = service["ErrorControl"]?.ToString() ?? "Unknown",
                                AcceptStop = Convert.ToBoolean(service["AcceptStop"] ?? false),
                                AcceptPause = Convert.ToBoolean(service["AcceptPause"] ?? false)
                            };

                            services.Add(serviceInfo);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "Failed to process WMI service object");
                        }
                        finally
                        {
                            service?.Dispose();
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate WMI services");
            }

            return services;
        }

        private async Task AnalyzeServiceVulnerabilities(List<ServiceInformation> services)
        {
            try
            {
                await Task.Run(() =>
                {
                    foreach (var service in services)
                    {
                        service.Vulnerabilities = new List<ServiceVulnerability>();

                        if (HasUnquotedServicePath(service))
                        {
                            service.Vulnerabilities.Add(new ServiceVulnerability
                            {
                                Type = "Unquoted Service Path",
                                Severity = "Medium",
                                Description = "Service path contains spaces but is not quoted",
                                ServiceName = service.ServiceName,
                                ExecutablePath = service.ExecutablePath,
                                Exploitable = true
                            });
                        }

                        if (HasWeakServicePermissions(service))
                        {
                            service.Vulnerabilities.Add(new ServiceVulnerability
                            {
                                Type = "Weak Service Permissions",
                                Severity = "High",
                                Description = "Service may have weak file or registry permissions",
                                ServiceName = service.ServiceName,
                                ExecutablePath = service.ExecutablePath,
                                Exploitable = true
                            });
                        }

                        if (IsRunningAsSystem(service))
                        {
                            service.Vulnerabilities.Add(new ServiceVulnerability
                            {
                                Type = "Privileged Service Account",
                                Severity = "Low",
                                Description = "Service runs under privileged account",
                                ServiceName = service.ServiceName,
                                Account = service.Account,
                                Exploitable = false
                            });
                        }

                        if (IsDeprecatedOrVulnerableService(service))
                        {
                            service.Vulnerabilities.Add(new ServiceVulnerability
                            {
                                Type = "Deprecated/Vulnerable Service",
                                Severity = "Medium",
                                Description = "Service may be deprecated or have known vulnerabilities",
                                ServiceName = service.ServiceName,
                                Exploitable = true
                            });
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service vulnerability analysis failed");
            }
        }

        private bool HasUnquotedServicePath(ServiceInformation service)
        {
            if (string.IsNullOrEmpty(service.ExecutablePath))
                return false;

            var path = service.ExecutablePath.Trim();

            if (path.StartsWith("\"") && path.EndsWith("\""))
                return false;

            return path.Contains(" ") && !path.StartsWith("C:\\Windows\\System32");
        }

        private bool HasWeakServicePermissions(ServiceInformation service)
        {
            if (string.IsNullOrEmpty(service.ExecutablePath))
                return false;

            var suspiciousPaths = new[]
            {
                "C:\\Program Files (x86)",
                "C:\\Program Files",
                "C:\\Users",
                "C:\\Temp",
                "C:\\Windows\\Temp"
            };

            return suspiciousPaths.Any(path =>
                service.ExecutablePath.StartsWith(path, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsRunningAsSystem(ServiceInformation service)
        {
            if (string.IsNullOrEmpty(service.Account))
                return false;

            var privilegedAccounts = new[]
            {
                "LocalSystem",
                "NT AUTHORITY\\SYSTEM",
                "NT AUTHORITY\\LocalService",
                "NT AUTHORITY\\NetworkService"
            };

            return privilegedAccounts.Any(account =>
                string.Equals(service.Account, account, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsDeprecatedOrVulnerableService(ServiceInformation service)
        {
            var vulnerableServices = new[]
            {
                "telnet", "ftp", "rsh", "rlogin", "finger", "nfs",
                "smb", "netbios", "snmp", "tftp"
            };

            return vulnerableServices.Any(vulnService =>
                service.ServiceName.Contains(vulnService, StringComparison.OrdinalIgnoreCase) ||
                service.DisplayName.Contains(vulnService, StringComparison.OrdinalIgnoreCase));
        }

        private string GetServiceStartType(string serviceName)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT StartMode FROM Win32_Service WHERE Name = '{serviceName}'");
                using var results = searcher.Get();

                foreach (ManagementObject result in results)
                {
                    return result["StartMode"]?.ToString() ?? "Unknown";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to get start type for service: {serviceName}");
            }

            return "Unknown";
        }

        private string GetServiceExecutablePath(string serviceName)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT PathName FROM Win32_Service WHERE Name = '{serviceName}'");
                using var results = searcher.Get();

                foreach (ManagementObject result in results)
                {
                    return result["PathName"]?.ToString() ?? "Unknown";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to get executable path for service: {serviceName}");
            }

            return "Unknown";
        }

        private string GetServiceDescription(string serviceName)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT Description FROM Win32_Service WHERE Name = '{serviceName}'");
                using var results = searcher.Get();

                foreach (ManagementObject result in results)
                {
                    return result["Description"]?.ToString() ?? "No description";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to get description for service: {serviceName}");
            }

            return "No description";
        }

        private string GetServiceAccount(string serviceName)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT StartName FROM Win32_Service WHERE Name = '{serviceName}'");
                using var results = searcher.Get();

                foreach (ManagementObject result in results)
                {
                    return result["StartName"]?.ToString() ?? "Unknown";
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to get account for service: {serviceName}");
            }

            return "Unknown";
        }
    }
}