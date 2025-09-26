using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.TaskScheduler;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Security.Principal;
using EliteWindowsPentestSuite.Core;
using EliteWindowsPentestSuite.Models.Results;
using EPenT.Core;

namespace EliteWindowsPentestSuite.Modules.Persistence
{
    public class ScheduledTaskPersistence : IDisposable
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ScheduledTaskPersistence> _logger;
        private readonly SecurityContext _securityContext;
        private TaskService _taskService;

        public ScheduledTaskPersistence(
            IConfiguration configuration,
            ILogger<ScheduledTaskPersistence> logger,
            SecurityContext securityContext)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));

            try
            {
                _taskService = new TaskService();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize Task Service");
            }
        }

        public async Task<ScheduledTaskPersistenceResult> ExecuteAsync()
        {
            _logger.LogInformation("Starting scheduled task persistence analysis");
            var result = new ScheduledTaskPersistenceResult();

            try
            {
                if (_taskService == null)
                {
                    result.AddError("Task Service not available");
                    result.Success = false;
                    return result;
                }

                await Task.Run(() => AnalyzeScheduledTasks(result));
                await Task.Run(() => AnalyzeTaskTriggers(result));
                await Task.Run(() => AnalyzeTaskActions(result));
                await Task.Run(() => AnalyzeTaskSecurity(result));

                result.TotalTasksAnalyzed = result.ScheduledTasks.Count;
                result.Success = true;
                result.ExecutionTime = DateTime.UtcNow;

                _logger.LogInformation($"Scheduled task analysis completed. Tasks analyzed: {result.TotalTasksAnalyzed}");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scheduled task persistence analysis failed");
                result.AddError($"Task analysis failed: {ex.Message}");
                result.Success = false;
                return result;
            }
        }

        public async Task<bool> EstablishPersistenceAsync(PersistenceOptions options)
        {
            try
            {
                _logger.LogInformation($"Creating scheduled task persistence: {options.Name}");

                if (_taskService == null)
                    return false;

                var taskDefinition = _taskService.NewTask();
                taskDefinition.RegistrationInfo.Description = options.Description ?? options.Name;
                taskDefinition.Principal.LogonType = TaskLogonType.InteractiveToken;
                taskDefinition.Principal.RunLevel = options.RunAsSystem ? TaskRunLevel.Highest : TaskRunLevel.LUA;

                if (options.StartWithWindows)
                {
                    taskDefinition.Triggers.Add(new BootTrigger());
                }
                else
                {
                    var logonTrigger = new LogonTrigger();
                    if (options.DelayMinutes > 0)
                    {
                        logonTrigger.Delay = TimeSpan.FromMinutes(options.DelayMinutes);
                    }
                    taskDefinition.Triggers.Add(logonTrigger);
                }

                var execAction = new ExecAction(options.PayloadPath, options.Arguments);
                taskDefinition.Actions.Add(execAction);

                taskDefinition.Settings.AllowDemandStart = true;
                taskDefinition.Settings.DisallowStartIfOnBatteries = false;
                taskDefinition.Settings.StopIfGoingOnBatteries = false;
                taskDefinition.Settings.Hidden = true;
                taskDefinition.Settings.ExecutionTimeLimit = TimeSpan.Zero;

                var task = _taskService.RootFolder.RegisterTaskDefinition(options.Name, taskDefinition);

                _logger.LogInformation($"Scheduled task created successfully: {options.Name}");
                return task != null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to establish scheduled task persistence");
                return false;
            }
        }

        public async Task<bool> RemovePersistenceAsync(string taskName)
        {
            try
            {
                _logger.LogInformation($"Removing scheduled task persistence: {taskName}");

                if (_taskService == null)
                    return false;

                var task = _taskService.FindTask(taskName);
                if (task != null)
                {
                    _taskService.RootFolder.DeleteTask(taskName);
                    _logger.LogInformation($"Scheduled task removed successfully: {taskName}");
                    return true;
                }
                else
                {
                    _logger.LogWarning($"Scheduled task not found: {taskName}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove scheduled task persistence");
                return false;
            }
        }

        public async Task<List<PersistenceMechanism>> GetActiveMechanismsAsync()
        {
            var mechanisms = new List<PersistenceMechanism>();

            try
            {
                if (_taskService == null)
                    return mechanisms;

                foreach (var task in _taskService.AllTasks)
                {
                    try
                    {
                        var execAction = task.Definition.Actions.OfType<ExecAction>().FirstOrDefault();
                        if (execAction != null)
                        {
                            mechanisms.Add(new PersistenceMechanism
                            {
                                Identifier = task.Name,
                                Method = PersistenceMethod.ScheduledTask,
                                Location = task.Path,
                                Command = execAction.Path,
                                Arguments = execAction.Arguments,
                                IsActive = task.Enabled && task.State != TaskState.Disabled,
                                CreatedDate = task.Definition.RegistrationInfo.Date,
                                LastModified = task.LastWriteTime,
                                Properties = new Dictionary<string, object>
                                {
                                    ["State"] = task.State.ToString(),
                                    ["NextRunTime"] = task.NextRunTime,
                                    ["LastRunTime"] = task.LastRunTime,
                                    ["RunLevel"] = task.Definition.Principal.RunLevel.ToString()
                                }
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to process task: {task.Name} - {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active scheduled task mechanisms");
            }

            return mechanisms;
        }

        public async Task<bool> TestPersistenceAsync(string taskName)
        {
            try
            {
                if (_taskService == null)
                    return false;

                var task = _taskService.FindTask(taskName);
                return task != null && task.Enabled;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to test scheduled task persistence: {taskName}");
                return false;
            }
        }

        public async Task<bool> IsMethodAvailableAsync()
        {
            try
            {
                return _taskService != null && _taskService.Connected;
            }
            catch
            {
                return false;
            }
        }

        private void AnalyzeScheduledTasks(ScheduledTaskPersistenceResult result)
        {
            try
            {
                foreach (var task in _taskService.AllTasks)
                {
                    try
                    {
                        var taskInfo = new ScheduledTaskInfo
                        {
                            Name = task.Name,
                            Path = task.Path,
                            State = task.State.ToString(),
                            Enabled = task.Enabled,
                            Hidden = task.Definition.Settings.Hidden,
                            Author = task.Definition.RegistrationInfo.Author,
                            Description = task.Definition.RegistrationInfo.Description,
                            CreatedDate = task.Definition.RegistrationInfo.Date,
                            LastRunTime = task.LastRunTime,
                            NextRunTime = task.NextRunTime,
                            LastTaskResult = task.LastTaskResult,
                            NumberOfMissedRuns = task.NumberOfMissedRuns,
                            UserId = task.Definition.Principal.UserId,
                            RunLevel = task.Definition.Principal.RunLevel.ToString(),
                            LogonType = task.Definition.Principal.LogonType.ToString()
                        };

                        var execActions = task.Definition.Actions.OfType<ExecAction>().ToList();
                        foreach (var action in execActions)
                        {
                            taskInfo.Actions.Add(new TaskActionInfo
                            {
                                Type = "ExecAction",
                                Path = action.Path,
                                Arguments = action.Arguments,
                                WorkingDirectory = action.WorkingDirectory
                            });

                            if (!string.IsNullOrEmpty(action.Path))
                            {
                                taskInfo.FileExists = File.Exists(action.Path);
                                taskInfo.IsSuspicious = IsSuspiciousTask(taskInfo, action);
                            }
                        }

                        foreach (var trigger in task.Definition.Triggers)
                        {
                            taskInfo.Triggers.Add(new TaskTriggerInfo
                            {
                                Type = trigger.TriggerType.ToString(),
                                StartBoundary = trigger.StartBoundary,
                                EndBoundary = trigger.EndBoundary,
                                Enabled = trigger.Enabled,
                                Settings = GetTriggerSettings(trigger)
                            });
                        }

                        result.ScheduledTasks.Add(taskInfo);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to analyze task: {task.Name} - {ex.Message}");
                        result.AddError($"Task analysis failed: {task.Name}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze scheduled tasks");
                result.AddError("Scheduled task enumeration failed");
            }
        }

        private void AnalyzeTaskTriggers(ScheduledTaskPersistenceResult result)
        {
            try
            {
                foreach (var taskInfo in result.ScheduledTasks)
                {
                    var task = _taskService.FindTask(taskInfo.Name);
                    if (task != null)
                    {
                        foreach (var trigger in task.Definition.Triggers)
                        {
                            var triggerInfo = new TaskTriggerInfo
                            {
                                Type = trigger.TriggerType.ToString(),
                                StartBoundary = trigger.StartBoundary,
                                EndBoundary = trigger.EndBoundary,
                                Enabled = trigger.Enabled,
                                Settings = GetTriggerSettings(trigger)
                            };

                            switch (trigger.TriggerType)
                            {
                                case TaskTriggerType.Boot:
                                    triggerInfo.IsPersistent = true;
                                    break;
                                case TaskTriggerType.Logon:
                                    triggerInfo.IsPersistent = true;
                                    break;
                                case TaskTriggerType.Daily:
                                case TaskTriggerType.Weekly:
                                case TaskTriggerType.Monthly:
                                    triggerInfo.IsPersistent = true;
                                    break;
                            }

                            taskInfo.Triggers.Add(triggerInfo);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze task triggers");
                result.AddError("Task trigger analysis failed");
            }
        }

        private void AnalyzeTaskActions(ScheduledTaskPersistenceResult result)
        {
            try
            {
                foreach (var taskInfo in result.ScheduledTasks)
                {
                    foreach (var actionInfo in taskInfo.Actions)
                    {
                        if (!string.IsNullOrEmpty(actionInfo.Path) && File.Exists(actionInfo.Path))
                        {
                            try
                            {
                                var fileInfo = new FileInfo(actionInfo.Path);
                                actionInfo.FileSize = fileInfo.Length;
                                actionInfo.CreationTime = fileInfo.CreationTime;
                                actionInfo.LastWriteTime = fileInfo.LastWriteTime;
                                actionInfo.FileAttributes = fileInfo.Attributes.ToString();
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Failed to get file info for: {actionInfo.Path} - {ex.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze task actions");
                result.AddError("Task action analysis failed");
            }
        }

        private void AnalyzeTaskSecurity(ScheduledTaskPersistenceResult result)
        {
            try
            {
                foreach (var taskInfo in result.ScheduledTasks)
                {
                    var task = _taskService.FindTask(taskInfo.Name);
                    if (task?.Definition != null)
                    {
                        try
                        {
                            var principal = task.Definition.Principal;
                            taskInfo.SecurityContext = new TaskSecurityInfo
                            {
                                UserId = principal.UserId,
                                GroupId = principal.GroupId,
                                RunLevel = principal.RunLevel.ToString(),
                                LogonType = principal.LogonType.ToString(),
                                ProcessTokenSidType = principal.ProcessTokenSidType.ToString()
                            };

                            if (principal.RunLevel == TaskRunLevel.Highest)
                            {
                                taskInfo.SecurityContext.RequiresElevation = true;
                            }

                            if (string.IsNullOrEmpty(principal.UserId) ||
                                principal.UserId.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                            {
                                taskInfo.SecurityContext.RunsAsSystem = true;
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to analyze security for task: {taskInfo.Name} - {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze task security");
                result.AddError("Task security analysis failed");
            }
        }
    }
}