using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Core;
using EPenT.Models.Results;
using EPenT.Models.System;

namespace EPenT.Modules.Reconnaissance
{
    public class ReconnaissanceModule
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ReconnaissanceModule> _logger;
        private readonly SecurityContext _securityContext;
        private readonly NetworkScanner _networkScanner;
        private readonly ServiceEnumerator _serviceEnumerator;
        private readonly UserEnumerator _userEnumerator;
        private readonly ProcessAnalyzer _processAnalyzer;

        public ReconnaissanceModule(IConfiguration configuration, ILogger<ReconnaissanceModule> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            _networkScanner = new NetworkScanner(_configuration, _logger);
            _serviceEnumerator = new ServiceEnumerator(_configuration, _logger);
            _userEnumerator = new UserEnumerator(_configuration, _logger, _securityContext);
            _processAnalyzer = new ProcessAnalyzer(_configuration, _logger, _securityContext);
        }

        public async Task<ReconnaissanceResults> ExecuteAsync()
        {
            var results = new ReconnaissanceResults
            {
                ModuleName = "Reconnaissance",
                StartTime = DateTime.UtcNow,
                Success = true
            };

            try
            {
                _logger.LogInformation("Starting reconnaissance phase");

                if (IsNetworkScanEnabled())
                {
                    _logger.LogInformation("Executing network reconnaissance");
                    results.NetworkInformation = await _networkScanner.ScanNetworkAsync();
                }

                if (IsServiceEnumEnabled())
                {
                    _logger.LogInformation("Executing service enumeration");
                    results.Services = await _serviceEnumerator.EnumerateServicesAsync();
                }

                if (IsUserEnumEnabled())
                {
                    _logger.LogInformation("Executing user enumeration");
                    results.Users = await _userEnumerator.EnumerateUsersAsync();
                }

                if (IsProcessAnalysisEnabled())
                {
                    _logger.LogInformation("Executing process analysis");
                    results.Processes = await _processAnalyzer.AnalyzeProcessesAsync();
                }

                results.SystemInformation = await GatherSystemInformation();
                results.EndTime = DateTime.UtcNow;
                results.Duration = results.EndTime - results.StartTime;

                _logger.LogInformation($"Reconnaissance completed in {results.Duration.TotalSeconds:F2} seconds");
                LogReconnaissanceResults(results);

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Reconnaissance module execution failed");
                results.Success = false;
                results.ErrorMessage = ex.Message;
                results.EndTime = DateTime.UtcNow;
                return results;
            }
        }

        private async Task<SystemInformation> GatherSystemInformation()
        {
            try
            {
                var systemInfo = new SystemInformation
                {
                    HostName = Environment.MachineName,
                    OperatingSystem = Environment.OSVersion.ToString(),
                    Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86",
                    ProcessorCount = Environment.ProcessorCount,
                    UserName = Environment.UserName,
                    UserDomainName = Environment.UserDomainName,
                    WorkingSet = Environment.WorkingSet,
                    SystemDirectory = Environment.SystemDirectory,
                    CurrentDirectory = Environment.CurrentDirectory,
                    CommandLine = Environment.CommandLine,
                    Version = Environment.Version.ToString(),
                    IsPrivileged = _securityContext.IsElevated,
                    IsSystem = _securityContext.IsSystem,
                    Privileges = _securityContext.Privileges
                };

                await Task.CompletedTask;
                return systemInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to gather system information");
                return new SystemInformation { HostName = "Unknown" };
            }
        }

        private bool IsNetworkScanEnabled()
        {
            return _configuration.GetValue<bool>("Modules:Reconnaissance:NetworkScan", true);
        }

        private bool IsServiceEnumEnabled()
        {
            return _configuration.GetValue<bool>("Modules:Reconnaissance:ServiceEnum", true);
        }

        private bool IsUserEnumEnabled()
        {
            return _configuration.GetValue<bool>("Modules:Reconnaissance:UserEnum", true);
        }

        private bool IsProcessAnalysisEnabled()
        {
            return _configuration.GetValue<bool>("Modules:Reconnaissance:ProcessAnalysis", true);
        }

        private void LogReconnaissanceResults(ReconnaissanceResults results)
        {
            _logger.LogInformation("Reconnaissance Results Summary:");
            _logger.LogInformation($"  System: {results.SystemInformation?.HostName ?? "Unknown"}");
            _logger.LogInformation($"  Services Found: {results.Services?.Count ?? 0}");
            _logger.LogInformation($"  Users Found: {results.Users?.Count ?? 0}");
            _logger.LogInformation($"  Processes Analyzed: {results.Processes?.Count ?? 0}");
            _logger.LogInformation($"  Network Hosts: {results.NetworkInformation?.DiscoveredHosts?.Count ?? 0}");
        }
    }
}