using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EliteWindowsPentestSuite.Models.Vulnerabilities;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.Persistence
{
    public class PersistenceModule
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<PersistenceModule> _logger;
        private readonly SecurityContext _securityContext;
        private readonly RegistryPersistence _registryPersistence;
        private readonly ServicePersistence _servicePersistence;
        private readonly ScheduledTaskPersistence _scheduledTaskPersistence;
        private readonly WMIPersistence _wmiPersistence;
        private readonly StartupPersistence _startupPersistence;
        private readonly COMHijacking _comHijacking;

        public PersistenceModule(
            IConfiguration configuration,
            ILogger<PersistenceModule> logger,
            SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            _registryPersistence = new RegistryPersistence(configuration, logger, securityContext);
            _servicePersistence = new ServicePersistence(configuration, logger, securityContext);
            _scheduledTaskPersistence = new ScheduledTaskPersistence(configuration, logger, securityContext);
            _wmiPersistence = new WMIPersistence(configuration, logger, securityContext);
            _startupPersistence = new StartupPersistence(configuration, logger, securityContext);
            _comHijacking = new COMHijacking(configuration, logger, securityContext);
        }

        public async Task<PersistenceResult> ExecuteAsync()
        {
            _logger.LogInformation("Starting persistence module execution");
            var result = new PersistenceResult();
            var tasks = new List<Task>();

            try
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var registryResult = await _registryPersistence.ExecuteAsync();
                        result.RegistryPersistence = registryResult;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Registry persistence execution failed");
                        result.AddError($"Registry persistence failed: {ex.Message}");
                    }
                }));

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var serviceResult = await _servicePersistence.ExecuteAsync();
                        result.ServicePersistence = serviceResult;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Service persistence execution failed");
                        result.AddError($"Service persistence failed: {ex.Message}");
                    }
                }));

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var taskResult = await _scheduledTaskPersistence.ExecuteAsync();
                        result.ScheduledTaskPersistence = taskResult;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Scheduled task persistence execution failed");
                        result.AddError($"Scheduled task persistence failed: {ex.Message}");
                    }
                }));

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var wmiResult = await _wmiPersistence.ExecuteAsync();
                        result.WMIPersistence = wmiResult;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "WMI persistence execution failed");
                        result.AddError($"WMI persistence failed: {ex.Message}");
                    }
                }));

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var startupResult = await _startupPersistence.ExecuteAsync();
                        result.StartupPersistence = startupResult;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Startup persistence execution failed");
                        result.AddError($"Startup persistence failed: {ex.Message}");
                    }
                }));

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var comResult = await _comHijacking.ExecuteAsync();
                        result.COMHijacking = comResult;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "COM hijacking execution failed");
                        result.AddError($"COM hijacking failed: {ex.Message}");
                    }
                }));

                await Task.WhenAll(tasks);

                result.ExecutionTime = DateTime.UtcNow;
                result.Success = !result.Errors.Any();
                result.TotalPersistenceMechanisms = GetTotalMechanismsCount(result);

                _logger.LogInformation($"Persistence module execution completed. Success: {result.Success}");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Critical error in persistence module execution");
                result.AddError($"Critical persistence module error: {ex.Message}");
                result.Success = false;
                return result;
            }
        }

        public async Task<bool> EstablishPersistenceAsync(PersistenceMethod method, PersistenceOptions options)
        {
            try
            {
                _logger.LogInformation($"Establishing persistence using method: {method}");

                switch (method)
                {
                    case PersistenceMethod.Registry:
                        return await _registryPersistence.EstablishPersistenceAsync(options);
                    case PersistenceMethod.Service:
                        return await _servicePersistence.EstablishPersistenceAsync(options);
                    case PersistenceMethod.ScheduledTask:
                        return await _scheduledTaskPersistence.EstablishPersistenceAsync(options);
                    case PersistenceMethod.WMI:
                        return await _wmiPersistence.EstablishPersistenceAsync(options);
                    case PersistenceMethod.Startup:
                        return await _startupPersistence.EstablishPersistenceAsync(options);
                    case PersistenceMethod.COMHijacking:
                        return await _comHijacking.EstablishPersistenceAsync(options);
                    default:
                        throw new ArgumentException($"Unknown persistence method: {method}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to establish persistence using method: {method}");
                return false;
            }
        }

        public async Task<bool> RemovePersistenceAsync(PersistenceMethod method, string identifier)
        {
            try
            {
                _logger.LogInformation($"Removing persistence using method: {method}, identifier: {identifier}");

                switch (method)
                {
                    case PersistenceMethod.Registry:
                        return await _registryPersistence.RemovePersistenceAsync(identifier);
                    case PersistenceMethod.Service:
                        return await _servicePersistence.RemovePersistenceAsync(identifier);
                    case PersistenceMethod.ScheduledTask:
                        return await _scheduledTaskPersistence.RemovePersistenceAsync(identifier);
                    case PersistenceMethod.WMI:
                        return await _wmiPersistence.RemovePersistenceAsync(identifier);
                    case PersistenceMethod.Startup:
                        return await _startupPersistence.RemovePersistenceAsync(identifier);
                    case PersistenceMethod.COMHijacking:
                        return await _comHijacking.RemovePersistenceAsync(identifier);
                    default:
                        throw new ArgumentException($"Unknown persistence method: {method}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to remove persistence using method: {method}");
                return false;
            }
        }

        public async Task<List<PersistenceMechanism>> GetActivePersistenceMechanismsAsync()
        {
            var mechanisms = new List<PersistenceMechanism>();

            try
            {
                var registryMechanisms = await _registryPersistence.GetActiveMechanismsAsync();
                mechanisms.AddRange(registryMechanisms);

                var serviceMechanisms = await _servicePersistence.GetActiveMechanismsAsync();
                mechanisms.AddRange(serviceMechanisms);

                var taskMechanisms = await _scheduledTaskPersistence.GetActiveMechanismsAsync();
                mechanisms.AddRange(taskMechanisms);

                var wmiMechanisms = await _wmiPersistence.GetActiveMechanismsAsync();
                mechanisms.AddRange(wmiMechanisms);

                var startupMechanisms = await _startupPersistence.GetActiveMechanismsAsync();
                mechanisms.AddRange(startupMechanisms);

                var comMechanisms = await _comHijacking.GetActiveMechanismsAsync();
                mechanisms.AddRange(comMechanisms);

                return mechanisms.OrderBy(m => m.Method).ThenBy(m => m.Location).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve active persistence mechanisms");
                return mechanisms;
            }
        }

        public async Task<bool> TestPersistenceAsync(string identifier)
        {
            try
            {
                var mechanisms = await GetActivePersistenceMechanismsAsync();
                var mechanism = mechanisms.FirstOrDefault(m => m.Identifier == identifier);

                if (mechanism == null)
                {
                    _logger.LogWarning($"Persistence mechanism not found: {identifier}");
                    return false;
                }

                switch (mechanism.Method)
                {
                    case PersistenceMethod.Registry:
                        return await _registryPersistence.TestPersistenceAsync(identifier);
                    case PersistenceMethod.Service:
                        return await _servicePersistence.TestPersistenceAsync(identifier);
                    case PersistenceMethod.ScheduledTask:
                        return await _scheduledTaskPersistence.TestPersistenceAsync(identifier);
                    case PersistenceMethod.WMI:
                        return await _wmiPersistence.TestPersistenceAsync(identifier);
                    case PersistenceMethod.Startup:
                        return await _startupPersistence.TestPersistenceAsync(identifier);
                    case PersistenceMethod.COMHijacking:
                        return await _comHijacking.TestPersistenceAsync(identifier);
                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to test persistence: {identifier}");
                return false;
            }
        }

        public async Task<Dictionary<PersistenceMethod, bool>> GetMethodAvailabilityAsync()
        {
            var availability = new Dictionary<PersistenceMethod, bool>();

            try
            {
                availability[PersistenceMethod.Registry] = await _registryPersistence.IsMethodAvailableAsync();
                availability[PersistenceMethod.Service] = await _servicePersistence.IsMethodAvailableAsync();
                availability[PersistenceMethod.ScheduledTask] = await _scheduledTaskPersistence.IsMethodAvailableAsync();
                availability[PersistenceMethod.WMI] = await _wmiPersistence.IsMethodAvailableAsync();
                availability[PersistenceMethod.Startup] = await _startupPersistence.IsMethodAvailableAsync();
                availability[PersistenceMethod.COMHijacking] = await _comHijacking.IsMethodAvailableAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check method availability");
            }

            return availability;
        }

        private int GetTotalMechanismsCount(PersistenceResult result)
        {
            int count = 0;

            if (result.RegistryPersistence?.DiscoveredMechanisms != null)
                count += result.RegistryPersistence.DiscoveredMechanisms.Count;
            if (result.ServicePersistence?.DiscoveredMechanisms != null)
                count += result.ServicePersistence.DiscoveredMechanisms.Count;
            if (result.ScheduledTaskPersistence?.DiscoveredMechanisms != null)
                count += result.ScheduledTaskPersistence.DiscoveredMechanisms.Count;
            if (result.WMIPersistence?.DiscoveredMechanisms != null)
                count += result.WMIPersistence.DiscoveredMechanisms.Count;
            if (result.StartupPersistence?.DiscoveredMechanisms != null)
                count += result.StartupPersistence.DiscoveredMechanisms.Count;
            if (result.COMHijacking?.DiscoveredMechanisms != null)
                count += result.COMHijacking.DiscoveredMechanisms.Count;

            return count;
        }

        public void Dispose()
        {
            _registryPersistence?.Dispose();
            _servicePersistence?.Dispose();
            _scheduledTaskPersistence?.Dispose();
            _wmiPersistence?.Dispose();
            _startupPersistence?.Dispose();
            _comHijacking?.Dispose();
        }
    }

    public enum PersistenceMethod
    {
        Registry,
        Service,
        ScheduledTask,
        WMI,
        Startup,
        COMHijacking
    }

    public class PersistenceOptions
    {
        public string PayloadPath { get; set; }
        public string Arguments { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public bool RunAsSystem { get; set; }
        public bool StartWithWindows { get; set; }
        public int DelayMinutes { get; set; }
        public Dictionary<string, object> AdditionalProperties { get; set; } = new Dictionary<string, object>();
    }

    public class PersistenceMechanism
    {
        public string Identifier { get; set; }
        public PersistenceMethod Method { get; set; }
        public string Location { get; set; }
        public string Command { get; set; }
        public string Arguments { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime LastModified { get; set; }
        public bool IsActive { get; set; }
        public string Hash { get; set; }
        public Dictionary<string, object> Properties { get; set; } = new Dictionary<string, object>();
    }
}