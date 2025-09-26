using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Models.Results;
using EPenT.Modules.Reconnaissance;
using EPenT.Modules.Exploitation;
using EPenT.Modules.DefenseEvasion;
using EPenT.Modules.CredentialAccess;
using EPenT.Modules.Persistence;
using EPenT.Modules.LateralMovement;
using EPenT.Modules.PostExploitation;
using EPenT.Modules.Exfiltration;
using EPenT.Modules.AntiForensics;

namespace EPenT.Core
{
    public class AssessmentEngine
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AssessmentEngine> _logger;
        private readonly SecurityContext _securityContext;

        private readonly Dictionary<string, Func<Task<object>>> _moduleExecutors;
        private readonly List<string> _executionOrder = new List<string>
        {
            "reconnaissance",
            "defenseevasion",
            "exploitation",
            "credentialaccess",
            "persistence",
            "lateralmovement",
            "postexploitation",
            "exfiltration",
            "antiforensics"
        };

        public AssessmentEngine(IConfiguration configuration, ILogger<AssessmentEngine> logger, SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            _moduleExecutors = InitializeModuleExecutors();
        }

        public async Task<AssessmentResults> ExecuteAssessment(string target, List<string> enabledModules, bool stealthMode, bool dryRun)
        {
            var results = new AssessmentResults
            {
                AssessmentId = Guid.NewGuid(),
                StartTime = DateTime.UtcNow,
                Target = target,
                Framework = "EliteWindowsPentestSuite",
                Version = "1.0.0",
                StealthMode = stealthMode,
                DryRun = dryRun,
                Success = true
            };

            try
            {
                _logger.LogInformation($"Starting assessment for target: {target}");

                if (enabledModules == null || !enabledModules.Any())
                {
                    enabledModules = _executionOrder;
                }

                var orderedModules = _executionOrder.Where(m =>
                    enabledModules.Any(e => string.Equals(e, m, StringComparison.OrdinalIgnoreCase))
                ).ToList();

                foreach (var moduleName in orderedModules)
                {
                    if (!IsModuleEnabled(moduleName))
                    {
                        _logger.LogInformation($"Skipping disabled module: {moduleName}");
                        continue;
                    }

                    try
                    {
                        _logger.LogInformation($"Executing module: {moduleName}");

                        if (stealthMode)
                        {
                            var delay = _configuration.GetValue<int>("Framework:StealthDelay", 5000);
                            await Task.Delay(delay);
                        }

                        var moduleResult = await ExecuteModule(moduleName, target, stealthMode, dryRun);
                        results.ModuleResults[moduleName] = moduleResult;

                        _logger.LogInformation($"Module {moduleName} completed successfully");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Module {moduleName} execution failed");
                        results.ModuleResults[moduleName] = new { Error = ex.Message, Success = false };
                        results.Success = false;
                    }
                }

                results.EndTime = DateTime.UtcNow;
                results.Duration = results.EndTime - results.StartTime;

                _logger.LogInformation($"Assessment completed. Duration: {results.Duration.TotalMinutes:F2} minutes");

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Assessment engine execution failed");
                results.Success = false;
                results.ErrorMessage = ex.Message;
                results.EndTime = DateTime.UtcNow;
                return results;
            }
        }

        private async Task<object> ExecuteModule(string moduleName, string target, bool stealthMode, bool dryRun)
        {
            if (!_moduleExecutors.ContainsKey(moduleName.ToLower()))
            {
                throw new InvalidOperationException($"Module {moduleName} not found");
            }

            var executor = _moduleExecutors[moduleName.ToLower()];
            return await executor();
        }

        private Dictionary<string, Func<Task<object>>> InitializeModuleExecutors()
        {
            return new Dictionary<string, Func<Task<object>>>(StringComparer.OrdinalIgnoreCase)
            {
                ["reconnaissance"] = async () =>
                {
                    var module = new ReconnaissanceModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["exploitation"] = async () =>
                {
                    var module = new ExploitationModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["defenseevasion"] = async () =>
                {
                    var module = new EvasionModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["credentialaccess"] = async () =>
                {
                    var module = new CredentialAccessModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["persistence"] = async () =>
                {
                    var module = new PersistenceModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["lateralmovement"] = async () =>
                {
                    var module = new LateralMovementModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["postexploitation"] = async () =>
                {
                    var module = new PostExploitationModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["exfiltration"] = async () =>
                {
                    var module = new ExfiltrationModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                },
                ["antiforensics"] = async () =>
                {
                    var module = new AntiForensicsModule(_configuration, _logger, _securityContext);
                    return await module.ExecuteAsync();
                }
            };
        }

        private bool IsModuleEnabled(string moduleName)
        {
            var configKey = $"Modules:{ToPascalCase(moduleName)}:Enabled";
            return _configuration.GetValue<bool>(configKey, false);
        }

        private string ToPascalCase(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return char.ToUpperInvariant(input[0]) + input.Substring(1).ToLowerInvariant();
        }
    }
}