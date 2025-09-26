using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Security.AccessControl;
using System.Security.Principal;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.Persistence
{
    public class StartupPersistence : IDisposable
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<StartupPersistence> _logger;
        private readonly SecurityContext _securityContext;
        private readonly List<string> _startupFolders;
        private readonly List<string> _shellFolders;

        public StartupPersistence(
            IConfiguration configuration,
            ILogger<StartupPersistence> logger,
            SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            _startupFolders = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup")
            };

            _shellFolders = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.SendTo),
                Environment.GetFolderPath(Environment.SpecialFolder.Recent),
                Environment.GetFolderPath(Environment.SpecialFolder.QuickLaunch)
            };
        }

        public async Task<StartupPersistenceResult> ExecuteAsync()
        {
            _logger.LogInformation("Starting startup persistence analysis");
            var result = new StartupPersistenceResult();

            try
            {
                await Task.Run(() => AnalyzeStartupFolders(result));
                await Task.Run(() => AnalyzeShellFolders(result));
                await Task.Run(() => AnalyzeSystemDirectories(result));
                await Task.Run(() => AnalyzeUserProfiles(result));

                result.TotalFilesAnalyzed = result.StartupFiles.Count + result.ShellFiles.Count + result.SystemFiles.Count;
                result.Success = true;
                result.ExecutionTime = DateTime.UtcNow;

                _logger.LogInformation($"Startup persistence analysis completed. Files analyzed: {result.TotalFilesAnalyzed}");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Startup persistence analysis failed");
                result.AddError($"Startup analysis failed: {ex.Message}");
                result.Success = false;
                return result;
            }
        }

        public async Task<bool> EstablishPersistenceAsync(PersistenceOptions options)
        {
            try
            {
                _logger.LogInformation($"Creating startup persistence: {options.Name}");

                var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                var linkPath = Path.Combine(startupFolder, $"{options.Name}.lnk");

                var created = await CreateShortcut(linkPath, options.PayloadPath, options.Arguments, options.Description);
                if (created)
                {
                    _logger.LogInformation($"Startup persistence created successfully: {options.Name}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to establish startup persistence");
                return false;
            }
        }

        public async Task<bool> RemovePersistenceAsync(string identifier)
        {
            try
            {
                _logger.LogInformation($"Removing startup persistence: {identifier}");

                var removed = false;

                foreach (var folder in _startupFolders)
                {
                    try
                    {
                        if (Directory.Exists(folder))
                        {
                            var files = Directory.GetFiles(folder, $"{identifier}*", SearchOption.TopDirectoryOnly);
                            foreach (var file in files)
                            {
                                File.Delete(file);
                                removed = true;
                                _logger.LogInformation($"Removed startup file: {file}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to remove files from startup folder: {folder} - {ex.Message}");
                    }
                }

                return removed;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove startup persistence");
                return false;
            }
        }

        public async Task<List<PersistenceMechanism>> GetActiveMechanismsAsync()
        {
            var mechanisms = new List<PersistenceMechanism>();

            try
            {
                foreach (var folder in _startupFolders)
                {
                    try
                    {
                        if (Directory.Exists(folder))
                        {
                            var files = Directory.GetFiles(folder, "*", SearchOption.TopDirectoryOnly);
                            foreach (var file in files)
                            {
                                var fileInfo = new FileInfo(file);
                                mechanisms.Add(new PersistenceMechanism
                                {
                                    Identifier = Path.GetFileNameWithoutExtension(file),
                                    Method = PersistenceMethod.Startup,
                                    Location = folder,
                                    Command = file,
                                    IsActive = true,
                                    CreatedDate = fileInfo.CreationTime,
                                    LastModified = fileInfo.LastWriteTime,
                                    Properties = new Dictionary<string, object>
                                    {
                                        ["FileSize"] = fileInfo.Length,
                                        ["Extension"] = fileInfo.Extension,
                                        ["Attributes"] = fileInfo.Attributes.ToString()
                                    }
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to enumerate startup folder: {folder} - {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active startup mechanisms");
            }

            return mechanisms;
        }

        public async Task<bool> TestPersistenceAsync(string identifier)
        {
            try
            {
                var mechanisms = await GetActiveMechanismsAsync();
                return mechanisms.Any(m => m.Identifier.Equals(identifier, StringComparison.OrdinalIgnoreCase) && m.IsActive);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to test startup persistence: {identifier}");
                return false;
            }
        }

        public async Task<bool> IsMethodAvailableAsync()
        {
            try
            {
                var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                return Directory.Exists(startupFolder);
            }
            catch
            {
                return false;
            }
        }

        private void AnalyzeStartupFolders(StartupPersistenceResult result)
        {
            foreach (var folder in _startupFolders)
            {
                try
                {
                    if (Directory.Exists(folder))
                    {
                        var files = Directory.GetFiles(folder, "*", SearchOption.TopDirectoryOnly);
                        foreach (var file in files)
                        {
                            try
                            {
                                var fileInfo = AnalyzeFile(file);
                                fileInfo.Location = folder;
                                fileInfo.Category = "Startup";
                                result.StartupFiles.Add(fileInfo);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Failed to analyze startup file: {file} - {ex.Message}");
                                result.AddError($"Startup file analysis failed: {file}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Failed to analyze startup folder: {folder} - {ex.Message}");
                    result.AddError($"Startup folder analysis failed: {folder}");
                }
            }
        }

        private void AnalyzeShellFolders(StartupPersistenceResult result)
        {
            foreach (var folder in _shellFolders)
            {
                try
                {
                    if (Directory.Exists(folder))
                    {
                        var files = Directory.GetFiles(folder, "*.lnk", SearchOption.TopDirectoryOnly);
                        foreach (var file in files)
                        {
                            try
                            {
                                var fileInfo = AnalyzeFile(file);
                                fileInfo.Location = folder;
                                fileInfo.Category = "Shell";

                                if (IsSuspiciousShortcut(file))
                                {
                                    fileInfo.IsSuspicious = true;
                                }

                                result.ShellFiles.Add(fileInfo);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Failed to analyze shell file: {file} - {ex.Message}");
                                result.AddError($"Shell file analysis failed: {file}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Failed to analyze shell folder: {folder} - {ex.Message}");
                    result.AddError($"Shell folder analysis failed: {folder}");
                }
            }
        }

        private void AnalyzeSystemDirectories(StartupPersistenceResult result)
        {
            var systemDirectories = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
                @"C:\Windows\System32\drivers",
                @"C:\Windows\SysWOW64\drivers"
            };

            foreach (var directory in systemDirectories)
            {
                try
                {
                    if (Directory.Exists(directory))
                    {
                        var files = Directory.GetFiles(directory, "*.exe", SearchOption.TopDirectoryOnly)
                                           .Concat(Directory.GetFiles(directory, "*.dll", SearchOption.TopDirectoryOnly))
                                           .Concat(Directory.GetFiles(directory, "*.sys", SearchOption.TopDirectoryOnly));

                        foreach (var file in files)
                        {
                            try
                            {
                                var fileInfo = AnalyzeFile(file);
                                fileInfo.Location = directory;
                                fileInfo.Category = "System";

                                if (IsSuspiciousSystemFile(file, fileInfo))
                                {
                                    fileInfo.IsSuspicious = true;
                                    result.SystemFiles.Add(fileInfo);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Failed to analyze system file: {file} - {ex.Message}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Failed to analyze system directory: {directory} - {ex.Message}");
                    result.AddError($"System directory analysis failed: {directory}");
                }
            }
        }

        private void AnalyzeUserProfiles(StartupPersistenceResult result)
        {
            try
            {
                var usersPath = @"C:\Users";
                if (Directory.Exists(usersPath))
                {
                    var userDirectories = Directory.GetDirectories(usersPath);
                    foreach (var userDir in userDirectories)
                    {
                        var userName = Path.GetFileName(userDir);
                        if (userName.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                            userName.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                            userName.Equals("All Users", StringComparison.OrdinalIgnoreCase))
                            continue;

                        try
                        {
                            var userStartupPath = Path.Combine(userDir, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");
                            if (Directory.Exists(userStartupPath))
                            {
                                var files = Directory.GetFiles(userStartupPath, "*", SearchOption.TopDirectoryOnly);
                                foreach (var file in files)
                                {
                                    try
                                    {
                                        var fileInfo = AnalyzeFile(file);
                                        fileInfo.Location = userStartupPath;
                                        fileInfo.Category = "UserStartup";
                                        fileInfo.Owner = userName;
                                        result.StartupFiles.Add(fileInfo);
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogWarning($"Failed to analyze user startup file: {file} - {ex.Message}");
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to analyze user profile: {userDir} - {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze user profiles");
                result.AddError("User profile analysis failed");
            }
        }

        private StartupFileInfo AnalyzeFile(string filePath)
        {
            var fileInfo = new FileInfo(filePath);
            var startupFileInfo = new StartupFileInfo
            {
                FileName = fileInfo.Name,
                FilePath = filePath,
                FileSize = fileInfo.Length,
                CreationTime = fileInfo.CreationTime,
                LastWriteTime = fileInfo.LastWriteTime,
                LastAccessTime = fileInfo.LastAccessTime,
                Extension = fileInfo.Extension,
                Attributes = fileInfo.Attributes.ToString(),
                IsHidden = (fileInfo.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden,
                IsSystemFile = (fileInfo.Attributes & FileAttributes.System) == FileAttributes.System,
                IsReadOnly = fileInfo.IsReadOnly
            };

            try
            {
                var security = File.GetAccessControl(filePath);
                startupFileInfo.Owner = security.GetOwner(typeof(NTAccount))?.Value;

                var rules = security.GetAccessRules(true, true, typeof(NTAccount));
                startupFileInfo.HasWeakPermissions = CheckWeakPermissions(rules);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to get file security info: {filePath} - {ex.Message}");
            }

            startupFileInfo.IsSuspicious = IsSuspiciousFile(startupFileInfo);

            return startupFileInfo;
        }

        private bool IsSuspiciousFile(StartupFileInfo fileInfo)
        {
            var suspiciousExtensions = new[] { ".bat", ".cmd", ".scr", ".pif", ".com" };
            var suspiciousNames = new[] { "temp", "test", "update", "install", "setup" };
            var suspiciousLocations = new[] { @"\temp\", @"\appdata\local\temp\", @"\users\public\" };

            var extensionSuspicious = suspiciousExtensions.Contains(fileInfo.Extension.ToLower());
            var nameSuspicious = suspiciousNames.Any(name =>
                fileInfo.FileName.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
            var locationSuspicious = suspiciousLocations.Any(location =>
                fileInfo.FilePath.IndexOf(location, StringComparison.OrdinalIgnoreCase) >= 0);

            var sizeSuspicious = fileInfo.FileSize < 1024 || fileInfo.FileSize > 100 * 1024 * 1024;
            var timeSuspicious = fileInfo.CreationTime > DateTime.Now.AddDays(-1);
            var attributeSuspicious = fileInfo.IsHidden && !fileInfo.IsSystemFile;

            return extensionSuspicious || nameSuspicious || locationSuspicious ||
                   sizeSuspicious || timeSuspicious || attributeSuspicious || fileInfo.HasWeakPermissions;
        }

        private bool IsSuspiciousShortcut(string shortcutPath)
        {
            try
            {
                var suspiciousTargets = new[]
                {
                    "powershell",
                    "cmd.exe",
                    "wscript",
                    "cscript",
                    "mshta",
                    "rundll32",
                    @"\temp\",
                    @"\appdata\"
                };

                return suspiciousTargets.Any(target =>
                    shortcutPath.IndexOf(target, StringComparison.OrdinalIgnoreCase) >= 0);
            }
            catch
            {
                return false;
            }
        }

        private bool IsSuspiciousSystemFile(string filePath, StartupFileInfo fileInfo)
        {
            var recentlyModified = fileInfo.LastWriteTime > DateTime.Now.AddDays(-30);
            var unusualSize = fileInfo.FileSize < 10240 || fileInfo.FileSize > 50 * 1024 * 1024;
            var suspiciousName = fileInfo.FileName.Length < 5 ||
                               fileInfo.FileName.Contains("temp") ||
                               fileInfo.FileName.Contains("test");

            return recentlyModified && (unusualSize || suspiciousName);
        }

        private bool CheckWeakPermissions(AuthorizationRuleCollection rules)
        {
            try
            {
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Allow)
                    {
                        var identity = rule.IdentityReference.Value;
                        if (identity.Equals("Everyone", StringComparison.OrdinalIgnoreCase) ||
                            identity.Equals("Users", StringComparison.OrdinalIgnoreCase) ||
                            identity.Contains("Authenticated Users"))
                        {
                            if ((rule.FileSystemRights & FileSystemRights.Write) == FileSystemRights.Write ||
                                (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch
            {
            }

            return false;
        }

        private async Task<bool> CreateShortcut(string shortcutPath, string targetPath, string arguments, string description)
        {
            try
            {
                var shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
                var shortcut = shell.GetType().InvokeMember("CreateShortcut",
                    System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });

                shortcut.GetType().InvokeMember("TargetPath",
                    System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { targetPath });

                if (!string.IsNullOrEmpty(arguments))
                {
                    shortcut.GetType().InvokeMember("Arguments",
                        System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { arguments });
                }

                if (!string.IsNullOrEmpty(description))
                {
                    shortcut.GetType().InvokeMember("Description",
                        System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { description });
                }

                shortcut.GetType().InvokeMember("Save",
                    System.Reflection.BindingFlags.InvokeMethod, null, shortcut, null);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to create shortcut: {shortcutPath}");
                return false;
            }
        }

        public void Dispose()
        {
        }
    }

    public class StartupPersistenceResult
    {
        public List<StartupFileInfo> StartupFiles { get; set; } = new List<StartupFileInfo>();
        public List<StartupFileInfo> ShellFiles { get; set; } = new List<StartupFileInfo>();
        public List<StartupFileInfo> SystemFiles { get; set; } = new List<StartupFileInfo>();
        public List<PersistenceMechanism> DiscoveredMechanisms { get; set; } = new List<PersistenceMechanism>();
        public int TotalFilesAnalyzed { get; set; }
        public bool Success { get; set; }
        public DateTime ExecutionTime { get; set; }
        public List<string> Errors { get; set; } = new List<string>();

        public void AddError(string error)
        {
            Errors.Add(error);
        }
    }

    public class StartupFileInfo
    {
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public string Location { get; set; }
        public string Category { get; set; }
        public string Owner { get; set; }
        public long FileSize { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public DateTime LastAccessTime { get; set; }
        public string Extension { get; set; }
        public string Attributes { get; set; }
        public bool IsHidden { get; set; }
        public bool IsSystemFile { get; set; }
        public bool IsReadOnly { get; set; }
        public bool IsSuspicious { get; set; }
        public bool HasWeakPermissions { get; set; }
        public Dictionary<string, object> AdditionalProperties { get; set; } = new Dictionary<string, object>();
    }
}