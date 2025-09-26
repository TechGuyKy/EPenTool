using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Management;
using System.Linq;
using System.Security.Principal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Core;
using EPenT.Models.System;

namespace EPenT.Modules.Reconnaissance
{
    public class UserEnumerator
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<UserEnumerator> _logger;
        private readonly SecurityContext _securityContext;

        public UserEnumerator(IConfiguration configuration, ILogger<UserEnumerator> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
        }

        public async Task<List<UserInformation>> EnumerateUsersAsync()
        {
            var users = new List<UserInformation>();

            try
            {
                _logger.LogInformation("Starting user enumeration");

                var localUsers = await EnumerateLocalUsersAsync();
                users.AddRange(localUsers);

                if (_securityContext.IsElevated)
                {
                    var domainUsers = await EnumerateDomainUsersAsync();
                    users.AddRange(domainUsers);

                    var groupMembers = await EnumerateGroupMembersAsync();
                    MergeGroupMembershipData(users, groupMembers);
                }
                else
                {
                    _logger.LogWarning("Limited user enumeration due to insufficient privileges");
                }

                await AnalyzeUserPrivileges(users);

                _logger.LogInformation($"User enumeration completed. Found {users.Count} users");
                return users.OrderBy(u => u.Username).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "User enumeration failed");
                return users;
            }
        }

        private async Task<List<UserInformation>> EnumerateLocalUsersAsync()
        {
            var users = new List<UserInformation>();

            try
            {
                await Task.Run(() =>
                {
                    using var context = new PrincipalContext(ContextType.Machine);
                    using var searcher = new PrincipalSearcher(new UserPrincipal(context));

                    foreach (var result in searcher.FindAll())
                    {
                        if (result is UserPrincipal user)
                        {
                            try
                            {
                                var userInfo = new UserInformation
                                {
                                    Username = user.SamAccountName ?? "Unknown",
                                    FullName = user.DisplayName ?? user.Name ?? "Unknown",
                                    Description = user.Description ?? "No description",
                                    Enabled = user.Enabled ?? false,
                                    AccountExpirationDate = user.AccountExpirationDate,
                                    LastLogon = user.LastLogon,
                                    LastPasswordSet = user.LastPasswordSet,
                                    PasswordNeverExpires = user.PasswordNeverExpires,
                                    UserCannotChangePassword = user.UserCannotChangePassword,
                                    PasswordNotRequired = user.PasswordNotRequired,
                                    AccountLockoutTime = user.AccountLockoutTime,
                                    BadLogonCount = user.BadLogonCount,
                                    HomeDirectory = user.HomeDirectory,
                                    HomeDrive = user.HomeDrive,
                                    ScriptPath = user.ScriptPath,
                                    UserPrincipalName = user.UserPrincipalName,
                                    DistinguishedName = user.DistinguishedName,
                                    Sid = user.Sid?.ToString() ?? "Unknown",
                                    IsLocal = true,
                                    Groups = new List<string>()
                                };

                                var groupMemberships = GetUserGroups(user);
                                userInfo.Groups.AddRange(groupMemberships);

                                users.Add(userInfo);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, $"Failed to process user: {user.SamAccountName}");
                            }
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate local users");
            }

            return users;
        }

        private async Task<List<UserInformation>> EnumerateDomainUsersAsync()
        {
            var users = new List<UserInformation>();

            try
            {
                await Task.Run(() =>
                {
                    try
                    {
                        using var context = new PrincipalContext(ContextType.Domain);
                        using var searcher = new PrincipalSearcher(new UserPrincipal(context));

                        foreach (var result in searcher.FindAll().Take(100))
                        {
                            if (result is UserPrincipal user)
                            {
                                try
                                {
                                    var userInfo = new UserInformation
                                    {
                                        Username = user.SamAccountName ?? "Unknown",
                                        FullName = user.DisplayName ?? user.Name ?? "Unknown",
                                        Description = user.Description ?? "No description",
                                        Enabled = user.Enabled ?? false,
                                        AccountExpirationDate = user.AccountExpirationDate,
                                        LastLogon = user.LastLogon,
                                        LastPasswordSet = user.LastPasswordSet,
                                        PasswordNeverExpires = user.PasswordNeverExpires,
                                        UserCannotChangePassword = user.UserCannotChangePassword,
                                        PasswordNotRequired = user.PasswordNotRequired,
                                        AccountLockoutTime = user.AccountLockoutTime,
                                        BadLogonCount = user.BadLogonCount,
                                        UserPrincipalName = user.UserPrincipalName,
                                        DistinguishedName = user.DistinguishedName,
                                        Sid = user.Sid?.ToString() ?? "Unknown",
                                        IsLocal = false,
                                        Groups = new List<string>()
                                    };

                                    var groupMemberships = GetUserGroups(user);
                                    userInfo.Groups.AddRange(groupMemberships);

                                    users.Add(userInfo);
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogDebug(ex, $"Failed to process domain user: {user.SamAccountName}");
                                }
                            }
                        }
                    }
                    catch (PrincipalServerDownException)
                    {
                        _logger.LogWarning("Domain controller not accessible, skipping domain users");
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate domain users");
            }

            return users;
        }

        private async Task<Dictionary<string, List<string>>> EnumerateGroupMembersAsync()
        {
            var groupMembers = new Dictionary<string, List<string>>();

            try
            {
                await Task.Run(() =>
                {
                    using var context = new PrincipalContext(ContextType.Machine);
                    using var searcher = new PrincipalSearcher(new GroupPrincipal(context));

                    foreach (var result in searcher.FindAll())
                    {
                        if (result is GroupPrincipal group)
                        {
                            try
                            {
                                var members = new List<string>();

                                foreach (var member in group.GetMembers())
                                {
                                    if (member is UserPrincipal user)
                                    {
                                        members.Add(user.SamAccountName ?? "Unknown");
                                    }
                                }

                                if (members.Any())
                                {
                                    groupMembers[group.SamAccountName ?? "Unknown"] = members;
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, $"Failed to enumerate members for group: {group.SamAccountName}");
                            }
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate group members");
            }

            return groupMembers;
        }

        private List<string> GetUserGroups(UserPrincipal user)
        {
            var groups = new List<string>();

            try
            {
                foreach (var group in user.GetGroups())
                {
                    if (group is GroupPrincipal groupPrincipal)
                    {
                        groups.Add(groupPrincipal.SamAccountName ?? "Unknown");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, $"Failed to get groups for user: {user.SamAccountName}");
            }

            return groups;
        }

        private void MergeGroupMembershipData(List<UserInformation> users, Dictionary<string, List<string>> groupMembers)
        {
            try
            {
                foreach (var user in users)
                {
                    foreach (var groupMembership in groupMembers)
                    {
                        if (groupMembership.Value.Contains(user.Username, StringComparer.OrdinalIgnoreCase))
                        {
                            if (!user.Groups.Contains(groupMembership.Key, StringComparer.OrdinalIgnoreCase))
                            {
                                user.Groups.Add(groupMembership.Key);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to merge group membership data");
            }
        }

        private async Task AnalyzeUserPrivileges(List<UserInformation> users)
        {
            try
            {
                await Task.Run(() =>
                {
                    var privilegedGroups = new[]
                    {
                        "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins",
                        "Backup Operators", "Server Operators", "Account Operators", "Print Operators",
                        "Remote Desktop Users", "Power Users"
                    };

                    foreach (var user in users)
                    {
                        user.IsPrivileged = user.Groups.Any(group =>
                            privilegedGroups.Contains(group, StringComparer.OrdinalIgnoreCase));

                        user.IsServiceAccount = IsServiceAccount(user);
                        user.IsSystemAccount = IsSystemAccount(user);
                        user.HasWeakPassword = HasPotentialWeakPassword(user);
                        user.IsStaleAccount = IsStaleAccount(user);
                        user.PrivilegeLevel = DeterminePrivilegeLevel(user);
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "User privilege analysis failed");
            }
        }

        private bool IsServiceAccount(UserInformation user)
        {
            var serviceIndicators = new[] { "service", "svc", "sql", "iis", "exchange", "sharepoint", "system" };

            return serviceIndicators.Any(indicator =>
                user.Username.Contains(indicator, StringComparison.OrdinalIgnoreCase) ||
                user.FullName.Contains(indicator, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsSystemAccount(UserInformation user)
        {
            var systemAccounts = new[]
            {
                "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DefaultAccount",
                "WDAGUtilityAccount", "Guest", "Administrator"
            };

            return systemAccounts.Contains(user.Username, StringComparer.OrdinalIgnoreCase);
        }

        private bool HasPotentialWeakPassword(UserInformation user)
        {
            if (user.PasswordNotRequired) return true;
            if (user.PasswordNeverExpires && user.LastPasswordSet.HasValue &&
                DateTime.Now - user.LastPasswordSet.Value > TimeSpan.FromDays(365)) return true;

            return false;
        }

        private bool IsStaleAccount(UserInformation user)
        {
            if (!user.Enabled) return true;
            if (user.LastLogon.HasValue && DateTime.Now - user.LastLogon.Value > TimeSpan.FromDays(90)) return true;
            if (user.AccountExpirationDate.HasValue && user.AccountExpirationDate.Value < DateTime.Now) return true;

            return false;
        }

        private string DeterminePrivilegeLevel(UserInformation user)
        {
            if (user.IsSystemAccount) return "System";
            if (user.Groups.Any(g => g.Equals("Administrators", StringComparison.OrdinalIgnoreCase) ||
                                    g.Equals("Domain Admins", StringComparison.OrdinalIgnoreCase))) return "Administrator";
            if (user.IsPrivileged) return "Privileged";
            if (user.IsServiceAccount) return "Service";
            return "Standard";
        }
    }
}