using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using EPenT.Models.Security;

namespace EPenT.Core
{
    public class SecurityContext
    {
        private readonly ILogger<SecurityContext> _logger;

        private WindowsIdentity? _currentIdentity;
        private WindowsPrincipal? _currentPrincipal;
        private bool _isElevated;
        private bool _isSystem;
        private string _username = string.Empty;
        private string _domain = string.Empty;
        private List<string> _privileges = new List<string>();
        private AccessToken? _currentToken;

        public bool IsInitialized { get; private set; }
        public bool IsElevated => _isElevated;
        public bool IsSystem => _isSystem;
        public string Username => _username;
        public string Domain => _domain;
        public List<string> Privileges => new List<string>(_privileges);
        public AccessToken? CurrentToken => _currentToken;

        public SecurityContext(ILogger<SecurityContext> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Initializing security context");

                await Task.Run(() =>
                {
                    _currentIdentity = WindowsIdentity.GetCurrent();
                    _currentPrincipal = new WindowsPrincipal(_currentIdentity);

                    _isElevated = _currentPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
                    _isSystem = _currentIdentity.IsSystem;

                    if (_currentIdentity.Name != null)
                    {
                        var nameParts = _currentIdentity.Name.Split('\\');
                        if (nameParts.Length == 2)
                        {
                            _domain = nameParts[0];
                            _username = nameParts[1];
                        }
                        else
                        {
                            _username = _currentIdentity.Name;
                        }
                    }

                    LoadPrivileges();
                    LoadTokenInformation();
                });

                IsInitialized = true;
                LogSecurityContext();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize security context");
                throw;
            }
        }

        public bool HasPrivilege(string privilege)
        {
            return _privileges.Contains(privilege, StringComparer.OrdinalIgnoreCase);
        }

        public async Task<bool> ElevatePrivilegesAsync()
        {
            try
            {
                if (_isElevated)
                {
                    _logger.LogInformation("Already running with elevated privileges");
                    return true;
                }

                _logger.LogInformation("Attempting privilege elevation");

                var processStartInfo = new ProcessStartInfo
                {
                    FileName = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty,
                    UseShellExecute = true,
                    Verb = "runas",
                    Arguments = string.Join(" ", Environment.GetCommandLineArgs().Skip(1))
                };

                var elevatedProcess = Process.Start(processStartInfo);
                if (elevatedProcess != null)
                {
                    await elevatedProcess.WaitForExitAsync();
                    return elevatedProcess.ExitCode == 0;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to elevate privileges");
                return false;
            }
        }

        public async Task<bool> ImpersonateUserAsync(string username, string domain, string password)
        {
            try
            {
                _logger.LogInformation($"Attempting to impersonate user: {domain}\\{username}");

                IntPtr tokenHandle = IntPtr.Zero;
                bool success = LogonUser(username, domain, password,
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out tokenHandle);

                if (success && tokenHandle != IntPtr.Zero)
                {
                    var identity = new WindowsIdentity(tokenHandle);
                    var impersonationContext = identity.Impersonate();

                    _logger.LogInformation("User impersonation successful");
                    return true;
                }

                _logger.LogWarning("User impersonation failed");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "User impersonation failed with exception");
                return false;
            }
        }

        public List<SecurityProduct> GetSecurityProducts()
        {
            var products = new List<SecurityProduct>();

            try
            {
                var avProducts = GetAntivirusProducts();
                var firewallProducts = GetFirewallProducts();
                var edProducts = GetEndpointDetectionProducts();

                products.AddRange(avProducts);
                products.AddRange(firewallProducts);
                products.AddRange(edProducts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate security products");
            }

            return products;
        }

        private void LoadPrivileges()
        {
            try
            {
                _privileges.Clear();

                IntPtr tokenHandle = IntPtr.Zero;
                if (OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY, out tokenHandle))
                {
                    uint tokenInformationLength = 0;
                    GetTokenInformation(tokenHandle, TokenPrivileges, IntPtr.Zero, 0, out tokenInformationLength);

                    if (tokenInformationLength > 0)
                    {
                        IntPtr tokenInformation = Marshal.AllocHGlobal((int)tokenInformationLength);
                        if (GetTokenInformation(tokenHandle, TokenPrivileges, tokenInformation, tokenInformationLength, out tokenInformationLength))
                        {
                            var privilegeCount = Marshal.ReadInt32(tokenInformation);
                            for (int i = 0; i < privilegeCount; i++)
                            {
                                var privilegeName = GetPrivilegeName(tokenInformation, i);
                                if (!string.IsNullOrEmpty(privilegeName))
                                {
                                    _privileges.Add(privilegeName);
                                }
                            }
                        }
                        Marshal.FreeHGlobal(tokenInformation);
                    }
                    CloseHandle(tokenHandle);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load privileges");
            }
        }

        private void LoadTokenInformation()
        {
            try
            {
                _currentToken = new AccessToken
                {
                    TokenType = _isElevated ? "Elevated" : "Standard",
                    IntegrityLevel = GetTokenIntegrityLevel(),
                    SessionId = GetTokenSessionId(),
                    AuthenticationId = _currentIdentity?.AuthenticationType ?? "Unknown",
                    TokenSource = "Current Process"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load token information");
            }
        }

        private string GetTokenIntegrityLevel()
        {
            if (_isSystem) return "System";
            if (_isElevated) return "High";
            return "Medium";
        }

        private uint GetTokenSessionId()
        {
            try
            {
                return (uint)Process.GetCurrentProcess().SessionId;
            }
            catch
            {
                return 0;
            }
        }

        private List<SecurityProduct> GetAntivirusProducts()
        {
            var products = new List<SecurityProduct>();

            try
            {
                products.Add(new SecurityProduct
                {
                    Name = "Windows Defender",
                    Type = "Antivirus",
                    Status = "Unknown",
                    Version = "Unknown"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate antivirus products");
            }

            return products;
        }

        private List<SecurityProduct> GetFirewallProducts()
        {
            var products = new List<SecurityProduct>();

            try
            {
                products.Add(new SecurityProduct
                {
                    Name = "Windows Firewall",
                    Type = "Firewall",
                    Status = "Unknown",
                    Version = "Unknown"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate firewall products");
            }

            return products;
        }

        private List<SecurityProduct> GetEndpointDetectionProducts()
        {
            var products = new List<SecurityProduct>();

            try
            {
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate endpoint detection products");
            }

            return products;
        }

        private string GetPrivilegeName(IntPtr tokenInformation, int index)
        {
            try
            {
                return $"Privilege_{index}";
            }
            catch
            {
                return string.Empty;
            }
        }

        private void LogSecurityContext()
        {
            _logger.LogInformation("Security Context Initialized:");
            _logger.LogInformation($"  User: {_domain}\\{_username}");
            _logger.LogInformation($"  Elevated: {_isElevated}");
            _logger.LogInformation($"  System: {_isSystem}");
            _logger.LogInformation($"  Privileges: {_privileges.Count}");
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass,
            IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_PROVIDER_DEFAULT = 0;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TokenPrivileges = 3;
    }
}