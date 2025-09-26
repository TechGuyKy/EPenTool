using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.CredentialAccess
{
    public class CredentialAccessModule
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<CredentialAccessModule> _logger;
        private readonly SecurityContext _securityContext;
        private readonly LSASSAccess _lsassAccess;
        private readonly SAMExtraction _samExtraction;
        private readonly RegistryCredentials _registryCredentials;
        private readonly BrowserCredentials _browserCredentials;
        private readonly KerberosTickets _kerberosTickets;
        private readonly CredentialStore _credentialStore;

        public CredentialAccessModule(IConfiguration configuration, ILogger<CredentialAccessModule> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            _lsassAccess = new LSASSAccess(_configuration, _logger, _securityContext);
            _samExtraction = new SAMExtraction(_configuration, _logger, _securityContext);
            _registryCredentials = new RegistryCredentials(_configuration, _logger, _securityContext);
            _browserCredentials = new BrowserCredentials(_configuration, _logger, _securityContext);
            _kerberosTickets = new KerberosTickets(_configuration, _logger, _securityContext);
            _credentialStore = new CredentialStore(_configuration, _logger, _securityContext);
        }

        public async Task<CredentialResults> ExecuteAsync()
        {
            var results = new CredentialResults
            {
                ModuleName = "CredentialAccess",
                StartTime = DateTime.UtcNow,
                Success = true,
                LSASSResults = new List<LSASSAccessResult>(),
                SAMResults = new List<SAMExtractionResult>(),
                RegistryCredentialResults = new List<RegistryCredentialResult>(),
                BrowserCredentialResults = new List<BrowserCredentialResult>(),
                KerberosResults = new List<KerberosTicketResult>(),
                CredentialStoreResults = new List<CredentialStoreResult>()
            };

            try
            {
                _logger.LogInformation("Starting credential access assessment");

                if (!_securityContext.IsElevated)
                {
                    _logger.LogWarning("Running with limited privileges - some credential access techniques may not be available");
                }

                if (IsLSASSAccessEnabled())
                {
                    _logger.LogInformation("Executing LSASS memory access assessment");
                    results.LSASSResults = await _lsassAccess.ExecuteAsync();
                }

                if (IsSAMExtractionEnabled())
                {
                    _logger.LogInformation("Executing SAM database extraction assessment");
                    results.SAMResults = await _samExtraction.ExecuteAsync();
                }

                if (IsRegistryCredentialsEnabled())
                {
                    _logger.LogInformation("Executing registry credential extraction assessment");
                    results.RegistryCredentialResults = await _registryCredentials.ExecuteAsync();
                }

                if (IsBrowserCredentialsEnabled())
                {
                    _logger.LogInformation("Executing browser credential harvesting assessment");
                    results.BrowserCredentialResults = await _browserCredentials.ExecuteAsync();
                }

                if (IsKerberosTicketsEnabled())
                {
                    _logger.LogInformation("Executing Kerberos ticket extraction assessment");
                    results.KerberosResults = await _kerberosTickets.ExecuteAsync();
                }

                if (IsCredentialStoreEnabled())
                {
                    _logger.LogInformation("Executing Windows credential store assessment");
                    results.CredentialStoreResults = await _credentialStore.ExecuteAsync();
                }

                results.EndTime = DateTime.UtcNow;
                results.Duration = results.EndTime - results.StartTime;

                CompileCredentialResults(results);
                LogCredentialResults(results);

                _logger.LogInformation($"Credential access assessment completed in {results.Duration.TotalSeconds:F2} seconds");

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Credential access module execution failed");
                results.Success = false;
                results.ErrorMessage = ex.Message;
                results.EndTime = DateTime.UtcNow;
                return results;
            }
        }

        private void CompileCredentialResults(CredentialResults results)
        {
            try
            {
                results.TotalCredentialSources = 0;
                results.AccessibleSources = 0;
                results.ProtectedSources = 0;
                results.CredentialsFound = 0;

                results.TotalCredentialSources += results.LSASSResults.Count;
                results.AccessibleSources += results.LSASSResults.Count(r => r.Success);
                results.ProtectedSources += results.LSASSResults.Count(r => !r.Success);
                results.CredentialsFound += results.LSASSResults.Sum(r => r.CredentialsExtracted);

                results.TotalCredentialSources += results.SAMResults.Count;
                results.AccessibleSources += results.SAMResults.Count(r => r.Success);
                results.ProtectedSources += results.SAMResults.Count(r => !r.Success);
                results.CredentialsFound += results.SAMResults.Sum(r => r.HashesExtracted);

                results.TotalCredentialSources += results.RegistryCredentialResults.Count;
                results.AccessibleSources += results.RegistryCredentialResults.Count(r => r.Success);
                results.ProtectedSources += results.RegistryCredentialResults.Count(r => !r.Success);
                results.CredentialsFound += results.RegistryCredentialResults.Sum(r => r.CredentialsFound);

                results.TotalCredentialSources += results.BrowserCredentialResults.Count;
                results.AccessibleSources += results.BrowserCredentialResults.Count(r => r.Success);
                results.ProtectedSources += results.BrowserCredentialResults.Count(r => !r.Success);
                results.CredentialsFound += results.BrowserCredentialResults.Sum(r => r.PasswordsFound);

                results.TotalCredentialSources += results.KerberosResults.Count;
                results.AccessibleSources += results.KerberosResults.Count(r => r.Success);
                results.ProtectedSources += results.KerberosResults.Count(r => !r.Success);
                results.CredentialsFound += results.KerberosResults.Sum(r => r.TicketsExtracted);

                results.TotalCredentialSources += results.CredentialStoreResults.Count;
                results.AccessibleSources += results.CredentialStoreResults.Count(r => r.Success);
                results.ProtectedSources += results.CredentialStoreResults.Count(r => !r.Success);
                results.CredentialsFound += results.CredentialStoreResults.Sum(r => r.CredentialsFound);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to compile credential results");
            }
        }

        private bool IsLSASSAccessEnabled()
        {
            return _configuration.GetValue<bool>("Modules:CredentialAccess:LSASSAccess", false);
        }

        private bool IsSAMExtractionEnabled()
        {
            return _configuration.GetValue<bool>("Modules:CredentialAccess:SAMExtraction", true);
        }

        private bool IsRegistryCredentialsEnabled()
        {
            return _configuration.GetValue<bool>("Modules:CredentialAccess:RegistryCredentials", true);
        }

        private bool IsBrowserCredentialsEnabled()
        {
            return _configuration.GetValue<bool>("Modules:CredentialAccess:BrowserCredentials", true);
        }

        private bool IsKerberosTicketsEnabled()
        {
            return _configuration.GetValue<bool>("Modules:CredentialAccess:KerberosTickets", false);
        }

        private bool IsCredentialStoreEnabled()
        {
            return _configuration.GetValue<bool>("Modules:CredentialAccess:CredentialStore", true);
        }

        private void LogCredentialResults(CredentialResults results)
        {
            _logger.LogInformation("Credential Access Results Summary:");
            _logger.LogInformation($"  Total Credential Sources: {results.TotalCredentialSources}");
            _logger.LogInformation($"  Accessible Sources: {results.AccessibleSources}");
            _logger.LogInformation($"  Protected Sources: {results.ProtectedSources}");
            _logger.LogInformation($"  Credentials Found: {results.CredentialsFound}");
            _logger.LogInformation($"  LSASS Access Results: {results.LSASSResults.Count}");
            _logger.LogInformation($"  SAM Extraction Results: {results.SAMResults.Count}");
            _logger.LogInformation($"  Registry Credential Results: {results.RegistryCredentialResults.Count}");
            _logger.LogInformation($"  Browser Credential Results: {results.BrowserCredentialResults.Count}");
            _logger.LogInformation($"  Kerberos Ticket Results: {results.KerberosResults.Count}");
            _logger.LogInformation($"  Credential Store Results: {results.CredentialStoreResults.Count}");

            if (results.AccessibleSources > 0)
            {
                _logger.LogWarning($"⚠️  {results.AccessibleSources} credential sources are accessible");
            }

            if (results.CredentialsFound > 0)
            {
                _logger.LogWarning($"⚠️  {results.CredentialsFound} credentials found - secure credential storage recommended");
            }
        }
    }
}