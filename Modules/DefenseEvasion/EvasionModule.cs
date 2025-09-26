using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.DefenseEvasion
{
    public class EvasionModule
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EvasionModule> _logger;
        private readonly SecurityContext _securityContext;
        private readonly AMSIBypass _amsiBypass;
        private readonly ETWEvasion _etwEvasion;
        private readonly AntivirusEvasion _antivirusEvasion;
        private readonly ProcessInjection _processInjection;
        private readonly ProcessHollowing _processHollowing;
        private readonly DLLHijacking _dllHijacking;

        public EvasionModule(IConfiguration configuration, ILogger<EvasionModule> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            _amsiBypass = new AMSIBypass(_configuration, _logger, _securityContext);
            _etwEvasion = new ETWEvasion(_configuration, _logger, _securityContext);
            _antivirusEvasion = new AntivirusEvasion(_configuration, _logger, _securityContext);
            _processInjection = new ProcessInjection(_configuration, _logger, _securityContext);
            _processHollowing = new ProcessHollowing(_configuration, _logger, _securityContext);
            _dllHijacking = new DLLHijacking(_configuration, _logger, _securityContext);
        }

        public async Task<EvasionResults> ExecuteAsync()
        {
            var results = new EvasionResults
            {
                ModuleName = "DefenseEvasion",
                StartTime = DateTime.UtcNow,
                Success = true,
                AMSIBypassResults = new List<AMSIBypassResult>(),
                ETWEvasionResults = new List<ETWEvasionResult>(),
                AntivirusEvasionResults = new List<AntivirusEvasionResult>(),
                ProcessInjectionResults = new List<ProcessInjectionResult>(),
                ProcessHollowingResults = new List<ProcessHollowingResult>(),
                DLLHijackingResults = new List<DLLHijackingResult>()
            };

            try
            {
                _logger.LogInformation("Starting defense evasion assessment");

                if (!_securityContext.IsElevated)
                {
                    _logger.LogWarning("Running with limited privileges - some evasion techniques may not be testable");
                }

                if (IsAMSIBypassEnabled())
                {
                    _logger.LogInformation("Executing AMSI bypass assessment");
                    results.AMSIBypassResults = await _amsiBypass.ExecuteAsync();
                }

                if (IsETWEvasionEnabled())
                {
                    _logger.LogInformation("Executing ETW evasion assessment");
                    results.ETWEvasionResults = await _etwEvasion.ExecuteAsync();
                }

                if (IsAntivirusEvasionEnabled())
                {
                    _logger.LogInformation("Executing antivirus evasion assessment");
                    results.AntivirusEvasionResults = await _antivirusEvasion.ExecuteAsync();
                }

                if (IsProcessInjectionEnabled())
                {
                    _logger.LogInformation("Executing process injection assessment");
                    results.ProcessInjectionResults = await _processInjection.ExecuteAsync();
                }

                if (IsProcessHollowingEnabled())
                {
                    _logger.LogInformation("Executing process hollowing assessment");
                    results.ProcessHollowingResults = await _processHollowing.ExecuteAsync();
                }

                if (IsDLLHijackingEnabled())
                {
                    _logger.LogInformation("Executing DLL hijacking assessment");
                    results.DLLHijackingResults = await _dllHijacking.ExecuteAsync();
                }

                results.EndTime = DateTime.UtcNow;
                results.Duration = results.EndTime - results.StartTime;

                CompileEvasionResults(results);
                LogEvasionResults(results);

                _logger.LogInformation($"Defense evasion assessment completed in {results.Duration.TotalSeconds:F2} seconds");

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Defense evasion module execution failed");
                results.Success = false;
                results.ErrorMessage = ex.Message;
                results.EndTime = DateTime.UtcNow;
                return results;
            }
        }

        private void CompileEvasionResults(EvasionResults results)
        {
            try
            {
                results.TotalEvasionTechniques = 0;
                results.SuccessfulEvasions = 0;
                results.FailedEvasions = 0;

                results.TotalEvasionTechniques += results.AMSIBypassResults.Count;
                results.SuccessfulEvasions += results.AMSIBypassResults.Count(r => r.Success);
                results.FailedEvasions += results.AMSIBypassResults.Count(r => !r.Success);

                results.TotalEvasionTechniques += results.ETWEvasionResults.Count;
                results.SuccessfulEvasions += results.ETWEvasionResults.Count(r => r.Success);
                results.FailedEvasions += results.ETWEvasionResults.Count(r => !r.Success);

                results.TotalEvasionTechniques += results.AntivirusEvasionResults.Count;
                results.SuccessfulEvasions += results.AntivirusEvasionResults.Count(r => r.Success);
                results.FailedEvasions += results.AntivirusEvasionResults.Count(r => !r.Success);

                results.TotalEvasionTechniques += results.ProcessInjectionResults.Count;
                results.SuccessfulEvasions += results.ProcessInjectionResults.Count(r => r.Success);
                results.FailedEvasions += results.ProcessInjectionResults.Count(r => !r.Success);

                results.TotalEvasionTechniques += results.ProcessHollowingResults.Count;
                results.SuccessfulEvasions += results.ProcessHollowingResults.Count(r => r.Success);
                results.FailedEvasions += results.ProcessHollowingResults.Count(r => !r.Success);

                results.TotalEvasionTechniques += results.DLLHijackingResults.Count;
                results.SuccessfulEvasions += results.DLLHijackingResults.Count(r => r.Success);
                results.FailedEvasions += results.DLLHijackingResults.Count(r => !r.Success);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to compile evasion results");
            }
        }

        private bool IsAMSIBypassEnabled()
        {
            return _configuration.GetValue<bool>("Modules:DefenseEvasion:AMSIBypass", true);
        }

        private bool IsETWEvasionEnabled()
        {
            return _configuration.GetValue<bool>("Modules:DefenseEvasion:ETWEvasion", true);
        }

        private bool IsAntivirusEvasionEnabled()
        {
            return _configuration.GetValue<bool>("Modules:DefenseEvasion:AntivirusEvasion", true);
        }

        private bool IsProcessInjectionEnabled()
        {
            return _configuration.GetValue<bool>("Modules:DefenseEvasion:ProcessInjection", false);
        }

        private bool IsProcessHollowingEnabled()
        {
            return _configuration.GetValue<bool>("Modules:DefenseEvasion:ProcessHollowing", false);
        }

        private bool IsDLLHijackingEnabled()
        {
            return _configuration.GetValue<bool>("Modules:DefenseEvasion:DLLHijacking", true);
        }

        private void LogEvasionResults(EvasionResults results)
        {
            _logger.LogInformation("Defense Evasion Results Summary:");
            _logger.LogInformation($"  Total Evasion Techniques: {results.TotalEvasionTechniques}");
            _logger.LogInformation($"  Successful Evasions: {results.SuccessfulEvasions}");
            _logger.LogInformation($"  Failed Evasions: {results.FailedEvasions}");
            _logger.LogInformation($"  AMSI Bypass Results: {results.AMSIBypassResults.Count}");
            _logger.LogInformation($"  ETW Evasion Results: {results.ETWEvasionResults.Count}");
            _logger.LogInformation($"  Antivirus Evasion Results: {results.AntivirusEvasionResults.Count}");
            _logger.LogInformation($"  Process Injection Results: {results.ProcessInjectionResults.Count}");
            _logger.LogInformation($"  Process Hollowing Results: {results.ProcessHollowingResults.Count}");
            _logger.LogInformation($"  DLL Hijacking Results: {results.DLLHijackingResults.Count}");

            if (results.SuccessfulEvasions > 0)
            {
                _logger.LogWarning($" {results.SuccessfulEvasions} successful evasion techniques found");
            }
        }
    }
}