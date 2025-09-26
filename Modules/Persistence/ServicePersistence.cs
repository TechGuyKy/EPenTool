using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.ServiceProcess;
using System.Management;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.IO;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.Persistence
{
    public class ServicePersistence : IDisposable
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ServicePersistence> _logger;
        private readonly SecurityContext _securityContext;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl, string lpBinaryPathName,
            string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lp, string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        private const uint SERVICE_ALL_ACCESS = 0xF01FF;
        private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        private const uint SERVICE_AUTO_START = 0x00000002;
        private const uint SERVICE_DEMAND_START = 0x00000003;
        private const uint SERVICE_ERROR_NORMAL = 0x00000001;
        private const uint SERVICE_CONTROL_STOP = 0x00000001;

        public ServicePersistence(
            IConfiguration configuration,
            ILogger<ServicePersistence> logger,
            SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<ServicePersistenceResult> ExecuteAsync()
        {
            _logger.LogInformation("Starting service persistence analysis");
            var result = new ServicePersistenceResult();

            try
            {
                await Task.Run(() => AnalyzeWindowsServices(result));
                await Task.Run(() => AnalyzeServiceDependencies(result));
                await Task.Run(() => AnalyzeServiceConfigurations(result));
                await Task.Run(() => AnalyzeServicePermissions(result));

                result.TotalServicesAnalyzed = result.WindowsServices.Count;
                result.Success = true;
                result.ExecutionTime = DateTime.UtcNow;

                _logger.LogInformation($"Service persistence analysis completed. Services analyzed: {result.TotalServicesAnalyzed}");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service persistence analysis failed");
                result.AddError($"Service analysis failed: {ex.Message}");
                result.Success = false;
                return result;
            }
        }

        public async Task<bool> EstablishPersistenceAsync(PersistenceOptions options)
        {
            try
            {
                _logger.LogInformation($"Creating service persistence: {options.Name}");

                var scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                try
                {
                    var startType = options.StartWithWindows ? SERVICE_AUTO_START : SERVICE_DEMAND_START;
                    var binaryPath = !string.IsNullOrEmpty(options.Arguments)
                        ? $"\"{options.PayloadPath}\" {options.Arguments}"
                        : $"\"{options.PayloadPath}\"";

                    var service = CreateService(
                        scManager,
                        options.Name,
                        options.Description ?? options.Name,
                        SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS,
                        startType,
                        SERVICE_ERROR_NORMAL,
                        binaryPath,
                        null,
                        IntPtr.Zero,
                        null,
                        null,
                        null);

                    if (service == IntPtr.Zero)
                    {
                        var error = Marshal.GetLastWin32Error();
                        throw new Win32Exception(error);
                    }

                    CloseServiceHandle(service);
                    _logger.LogInformation($"Service created successfully: {options.Name}");

                    if (options.StartWithWindows)
                    {
                        await StartServiceAsync(options.Name);
                    }

                    return true;
                }
                finally
                {
                    CloseServiceHandle(scManager);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to establish service persistence");
                return false;
            }
        }

        public async Task<bool> RemovePersistenceAsync(string serviceName)
        {
            try
            {
                _logger.LogInformation($"Removing service persistence: {serviceName}");

                var scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                try
                {
                    var service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                    if (service == IntPtr.Zero)
                    {
                        _logger.LogWarning($"Service not found: {serviceName}");
                        return false;
                    }

                    try
                    {
                        var status = new SERVICE_STATUS();
                        ControlService(service, SERVICE_CONTROL_STOP, ref status);

                        await Task.Delay(2000);

                        var deleted = DeleteService(service);
                        if (!deleted)
                        {
                            var error = Marshal.GetLastWin32Error();
                            throw new Win32Exception(error);
                        }

                        _logger.LogInformation($"Service removed successfully: {serviceName}");
                        return true;
                    }
                    finally
                    {
                        CloseServiceHandle(service);
                    }
                }
                finally
                {
                    CloseServiceHandle(scManager);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove service persistence");
                return false;
            }
        }

        public async Task<List<PersistenceMechanism>> GetActiveMechanismsAsync()
        {
            var mechanisms = new List<PersistenceMechanism>();

            try
            {
                var services = ServiceController.GetServices();
                foreach (var service in services)
                {
                    try
                    {
                        using (var managementObject = new ManagementObject($"Win32_Service.Name='{service.ServiceName}'"))
                        {
                            managementObject.Get();
                            var pathName = managementObject["PathName"]?.ToString();
                            var startMode = managementObject["StartMode"]?.ToString();

                            if (!string.IsNullOrEmpty(pathName))
                            {
                                mechanisms.Add(new PersistenceMechanism
                                {
                                    Identifier = service.ServiceName,
                                    Method = PersistenceMethod.Service,
                                    Location = "Services",
                                    Command = pathName,
                                    IsActive = service.Status == ServiceControllerStatus.Running,
                                    CreatedDate = DateTime.UtcNow,
                                    LastModified = DateTime.UtcNow,
                                    Properties = new Dictionary<string, object>
                                    {
                                        ["StartMode"] = startMode,
                                        ["Status"] = service.Status.ToString(),
                                        ["DisplayName"] = service.DisplayName
                                    }
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to get service details: {service.ServiceName} - {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active service mechanisms");
            }

            return mechanisms;
        }

        public async Task<bool> TestPersistenceAsync(string serviceName)
        {
            try
            {
                var service = ServiceController.GetServices()
                    .FirstOrDefault(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));

                return service != null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to test service persistence: {serviceName}");
                return false;
            }
        }

        public async Task<bool> IsMethodAvailableAsync()
        {
            try
            {
                var scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager != IntPtr.Zero)
                {
                    CloseServiceHandle(scManager);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> StartServiceAsync(string serviceName)
        {
            try
            {
                var scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    return false;
                }

                try
                {
                    var service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                    if (service == IntPtr.Zero)
                    {
                        return false;
                    }

                    try
                    {
                        var started = StartService(service, 0, null);
                        return started;
                    }
                    finally
                    {
                        CloseServiceHandle(service);
                    }
                }
                finally
                {
                    CloseServiceHandle(scManager);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to start service: {serviceName}");
                return false;
            }
        }

        private void AnalyzeWindowsServices(ServicePersistenceResult result)
        {
            try
            {
                var services = ServiceController.GetServices();
                foreach (var service in services)
                {
                    try
                    {
                        using (var managementObject = new ManagementObject($"Win32_Service.Name='{service.ServiceName}'"))
                        {
                            managementObject.Get();

                            var serviceInfo = new ServiceInfo
                            {
                                Name = service.ServiceName,
                                DisplayName = service.DisplayName,
                                Status = service.Status.ToString(),
                                StartType = managementObject["StartMode"]?.ToString(),
                                PathName = managementObject["PathName"]?.ToString(),
                                ServiceType = managementObject["ServiceType"]?.ToString(),
                                Account = managementObject["StartName"]?.ToString(),
                                Description = managementObject["Description"]?.ToString()
                            };

                            if (!string.IsNullOrEmpty(serviceInfo.PathName))
                            {
                                serviceInfo.FileExists = File.Exists(ExtractFilePath(serviceInfo.PathName));
                                serviceInfo.IsSuspicious = IsSuspiciousService(serviceInfo);
                            }

                            result.WindowsServices.Add(serviceInfo);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to analyze service: {service.ServiceName} - {ex.Message}");
                        result.AddError($"Service analysis failed: {service.ServiceName}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze Windows services");
                result.AddError("Windows service enumeration failed");
            }
        }

        private void AnalyzeServiceDependencies(ServicePersistenceResult result)
        {
            try
            {
                foreach (var serviceInfo in result.WindowsServices)
                {
                    try
                    {
                        var service = ServiceController.GetServices()
                            .FirstOrDefault(s => s.ServiceName == serviceInfo.Name);

                        if (service != null)
                        {
                            serviceInfo.Dependencies = service.ServicesDependedOn
                                .Select(s => s.ServiceName)
                                .ToList();

                            serviceInfo.Dependents = service.DependentServices
                                .Select(s => s.ServiceName)
                                .ToList();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to analyze dependencies for service: {serviceInfo.Name} - {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze service dependencies");
                result.AddError("Service dependency analysis failed");
            }
        }

        private void AnalyzeServiceConfigurations(ServicePersistenceResult result)
        {
            try
            {
                var query = "SELECT * FROM Win32_Service";
                using (var searcher = new ManagementObjectSearcher(query))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        try
                        {
                            var serviceName = obj["Name"]?.ToString();
                            var serviceInfo = result.WindowsServices
                                .FirstOrDefault(s => s.Name == serviceName);

                            if (serviceInfo != null)
                            {
                                serviceInfo.ProcessId = Convert.ToInt32(obj["ProcessId"] ?? 0);
                                serviceInfo.ExitCode = Convert.ToInt32(obj["ExitCode"] ?? 0);
                                serviceInfo.State = obj["State"]?.ToString();
                                serviceInfo.AcceptStop = Convert.ToBoolean(obj["AcceptStop"] ?? false);
                                serviceInfo.AcceptPause = Convert.ToBoolean(obj["AcceptPause"] ?? false);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to get service configuration - {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze service configurations");
                result.AddError("Service configuration analysis failed");
            }
        }

        private void AnalyzeServicePermissions(ServicePersistenceResult result)
        {
            try
            {
                foreach (var serviceInfo in result.WindowsServices)
                {
                    try
                    {
                        if (!string.IsNullOrEmpty(serviceInfo.PathName))
                        {
                            var filePath = ExtractFilePath(serviceInfo.PathName);
                            if (File.Exists(filePath))
                            {
                                var fileInfo = new FileInfo(filePath);
                                serviceInfo.FileSize = fileInfo.Length;
                                serviceInfo.CreationTime = fileInfo.CreationTime;
                                serviceInfo.LastWriteTime = fileInfo.LastWriteTime;
                                serviceInfo.IsReadOnly = fileInfo.IsReadOnly;

                                serviceInfo.WeakPermissions = CheckWeakPermissions(filePath);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to analyze permissions for service: {serviceInfo.Name} - {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze service permissions");
                result.AddError("Service permission analysis failed");
            }
        }

        private string ExtractFilePath(string pathName)
        {
            if (string.IsNullOrEmpty(pathName))
                return string.Empty;

            pathName = pathName.Trim();

            if (pathName.StartsWith("\""))
            {
                var endQuote = pathName.IndexOf("\"", 1);
                if (endQuote > 0)
                {
                    return pathName.Substring(1, endQuote - 1);
                }
            }

            var spaceIndex = pathName.IndexOf(" ");
            return spaceIndex > 0 ? pathName.Substring(0, spaceIndex) : pathName;
        }

        private bool IsSuspiciousService(ServiceInfo serviceInfo)
        {
            if (string.IsNullOrEmpty(serviceInfo.PathName))
                return false;

            var suspiciousIndicators = new[]
            {
                @"\temp\",
                @"\appdata\",
                @"\users\public\",
                ".bat",
                ".cmd",
                ".scr",
                ".pif",
                "powershell",
                "cmd.exe",
                "wscript",
                "cscript",
                "mshta",
                "rundll32"
            };

            var pathSuspicious = suspiciousIndicators.Any(indicator =>
                serviceInfo.PathName.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0);

            var nameSuspicious = string.IsNullOrEmpty(serviceInfo.Description) ||
                                serviceInfo.Name.Length < 3 ||
                                serviceInfo.Name.Contains("temp") ||
                                serviceInfo.Name.Contains("test");

            var accountSuspicious = !string.IsNullOrEmpty(serviceInfo.Account) &&
                                   !serviceInfo.Account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) &&
                                   !serviceInfo.Account.Equals("NT AUTHORITY\\LocalService", StringComparison.OrdinalIgnoreCase) &&
                                   !serviceInfo.Account.Equals("NT AUTHORITY\\NetworkService", StringComparison.OrdinalIgnoreCase);

            return pathSuspicious || nameSuspicious || accountSuspicious;
        }

        private bool CheckWeakPermissions(string filePath)
        {
            try
            {
                var directoryPath = Path.GetDirectoryName(filePath);
                if (string.IsNullOrEmpty(directoryPath))
                    return false;

                var suspiciousPaths = new[]
                {
                    @"C:\temp",
                    @"C:\windows\temp",
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"C:\Users\Public"
                };

                return suspiciousPaths.Any(suspicious =>
                    directoryPath.StartsWith(suspicious, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
        }
    }

    public class ServicePersistenceResult
    {
        public List<ServiceInfo> WindowsServices { get; set; } = new List<ServiceInfo>();
        public List<PersistenceMechanism> DiscoveredMechanisms { get; set; } = new List<PersistenceMechanism>();
        public int TotalServicesAnalyzed { get; set; }
        public bool Success { get; set; }
        public DateTime ExecutionTime { get; set; }
        public List<string> Errors { get; set; } = new List<string>();

        public void AddError(string error)
        {
            Errors.Add(error);
        }
    }

    public class ServiceInfo
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Status { get; set; }
        public string StartType { get; set; }
        public string PathName { get; set; }
        public string ServiceType { get; set; }
        public string Account { get; set; }
        public string Description { get; set; }
        public string State { get; set; }
        public int ProcessId { get; set; }
        public int ExitCode { get; set; }
        public bool AcceptStop { get; set; }
        public bool AcceptPause { get; set; }
        public bool FileExists { get; set; }
        public bool IsSuspicious { get; set; }
        public bool WeakPermissions { get; set; }
        public bool IsReadOnly { get; set; }
        public long FileSize { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public List<string> Dependencies { get; set; } = new List<string>();
        public List<string> Dependents { get; set; } = new List<string>();
        public Dictionary<string, object> AdditionalProperties { get; set; } = new Dictionary<string, object>();
    }
}