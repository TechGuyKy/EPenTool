using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;

namespace EPenT.Core
{
    public class FrameworkConfiguration
    {
        private readonly IConfiguration _configuration;

        public FrameworkConfiguration(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public string DefaultTarget => _configuration.GetValue<string>("Framework:DefaultTarget", "localhost") ?? "localhost";

        public string DefaultOutputPath => _configuration.GetValue<string>("Framework:DefaultOutputPath", "./Output") ?? "./Output";

        public int MaxThreads => _configuration.GetValue<int>("Framework:MaxThreads", 10);

        public int DefaultTimeout => _configuration.GetValue<int>("Framework:DefaultTimeout", 30000);

        public int StealthDelay => _configuration.GetValue<int>("Framework:StealthDelay", 5000);

        public bool EnableTelemetry => _configuration.GetValue<bool>("Framework:EnableTelemetry", false);

        public bool RequireElevation => _configuration.GetValue<bool>("Security:RequireElevation", false);

        public bool ValidateTargets => _configuration.GetValue<bool>("Security:ValidateTargets", true);

        public bool LogAllActions => _configuration.GetValue<bool>("Security:LogAllActions", true);

        public bool EncryptLogs => _configuration.GetValue<bool>("Security:EncryptLogs", false);

        public bool AllowRemoteTargets => _configuration.GetValue<bool>("Security:AllowRemoteTargets", false);

        public int MaxAssessmentDuration => _configuration.GetValue<int>("Security:MaxAssessmentDuration", 7200000);

        public bool IsModuleEnabled(string moduleName)
        {
            var configKey = $"Modules:{ToPascalCase(moduleName)}:Enabled";
            return _configuration.GetValue<bool>(configKey, false);
        }

        public T GetModuleConfiguration<T>(string moduleName, string configName, T defaultValue)
        {
            var configKey = $"Modules:{ToPascalCase(moduleName)}:{configName}";
            return _configuration.GetValue<T>(configKey, defaultValue);
        }

        public bool IsExploitEnabled(string category, string exploitName)
        {
            var configKey = $"Exploits:{category}:{exploitName}";
            return _configuration.GetValue<bool>(configKey, false);
        }

        public bool IsPayloadEnabled(string category, string payloadName)
        {
            var configKey = $"Payloads:{category}:{payloadName}";
            return _configuration.GetValue<bool>(configKey, false);
        }

        public List<int> GetNetworkPorts()
        {
            var ports = new List<int>();
            var configPorts = _configuration.GetSection("Network:DefaultPorts").Get<int[]>();
            if (configPorts != null)
            {
                ports.AddRange(configPorts);
            }

            if (ports.Count == 0)
            {
                ports.AddRange(new int[]
                {
                    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 8080, 8443
                });
            }

            return ports;
        }

        public int GetNetworkScanTimeout()
        {
            return _configuration.GetValue<int>("Network:ScanTimeout", 5000);
        }

        public int GetMaxConcurrentScans()
        {
            return _configuration.GetValue<int>("Network:MaxConcurrentScans", 50);
        }

        public bool IsPortScanEnabled()
        {
            return _configuration.GetValue<bool>("Network:EnablePortScan", true);
        }

        public bool IsServiceDetectionEnabled()
        {
            return _configuration.GetValue<bool>("Network:EnableServiceDetection", true);
        }

        public bool IsOSDetectionEnabled()
        {
            return _configuration.GetValue<bool>("Network:EnableOSDetection", false);
        }

        public string GetWordlistPath(string wordlistType)
        {
            var configKey = $"WordLists:{wordlistType}";
            return _configuration.GetValue<string>(configKey, string.Empty) ?? string.Empty;
        }

        public string GetOutputDirectory(string directoryType)
        {
            var configKey = $"Output:{directoryType}Directory";
            var defaultPath = $"./Output/{directoryType}";
            return _configuration.GetValue<string>(configKey, defaultPath) ?? defaultPath;
        }

        public int GetRetentionDays()
        {
            return _configuration.GetValue<int>("Output:RetentionDays", 30);
        }

        public bool ShouldCompressOldReports()
        {
            return _configuration.GetValue<bool>("Output:CompressOldReports", true);
        }

        public bool ShouldGenerateHTML()
        {
            return _configuration.GetValue<bool>("Reporting:GenerateHTML", true);
        }

        public bool ShouldGenerateJSON()
        {
            return _configuration.GetValue<bool>("Reporting:GenerateJSON", true);
        }

        public bool ShouldGenerateCSV()
        {
            return _configuration.GetValue<bool>("Reporting:GenerateCSV", false);
        }

        public bool ShouldGeneratePDF()
        {
            return _configuration.GetValue<bool>("Reporting:GeneratePDF", false);
        }

        public bool ShouldGenerateExecutiveSummary()
        {
            return _configuration.GetValue<bool>("Reporting:ExecutiveSummary", true);
        }

        public bool ShouldIncludeDetailedFindings()
        {
            return _configuration.GetValue<bool>("Reporting:DetailedFindings", true);
        }

        public bool ShouldIncludeScreenshots()
        {
            return _configuration.GetValue<bool>("Reporting:IncludeScreenshots", false);
        }

        public bool ShouldIncludeEvidence()
        {
            return _configuration.GetValue<bool>("Reporting:IncludeEvidence", true);
        }

        public Dictionary<string, object> GetModuleSettings(string moduleName)
        {
            var settings = new Dictionary<string, object>();
            var section = _configuration.GetSection($"Modules:{ToPascalCase(moduleName)}");

            foreach (var child in section.GetChildren())
            {
                if (child.Value != null)
                {
                    settings[child.Key] = child.Value;
                }
            }

            return settings;
        }

        public Dictionary<string, object> GetExploitSettings(string category)
        {
            var settings = new Dictionary<string, object>();
            var section = _configuration.GetSection($"Exploits:{category}");

            foreach (var child in section.GetChildren())
            {
                if (child.Value != null)
                {
                    settings[child.Key] = bool.TryParse(child.Value, out bool boolValue) ? boolValue : child.Value;
                }
            }

            return settings;
        }

        public Dictionary<string, object> GetPayloadSettings(string category)
        {
            var settings = new Dictionary<string, object>();
            var section = _configuration.GetSection($"Payloads:{category}");

            foreach (var child in section.GetChildren())
            {
                if (child.Value != null)
                {
                    settings[child.Key] = bool.TryParse(child.Value, out bool boolValue) ? boolValue : child.Value;
                }
            }

            return settings;
        }

        public string GetLogLevel()
        {
            return _configuration.GetValue<string>("Logging:LogLevel:Default", "Information") ?? "Information";
        }

        public bool IsVerboseLoggingEnabled()
        {
            var logLevel = GetLogLevel();
            return string.Equals(logLevel, "Debug", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(logLevel, "Trace", StringComparison.OrdinalIgnoreCase);
        }

        public TimeSpan GetModuleTimeout(string moduleName)
        {
            var timeoutMs = _configuration.GetValue<int>($"Modules:{ToPascalCase(moduleName)}:Timeout", DefaultTimeout);
            return TimeSpan.FromMilliseconds(timeoutMs);
        }

        public bool IsSafeModeEnabled(string moduleName)
        {
            return _configuration.GetValue<bool>($"Modules:{ToPascalCase(moduleName)}:SafeMode", true);
        }

        public string GetConfigurationValue(string key, string defaultValue = "")
        {
            return _configuration.GetValue<string>(key, defaultValue) ?? defaultValue;
        }

        public T GetConfigurationValue<T>(string key, T defaultValue)
        {
            return _configuration.GetValue<T>(key, defaultValue);
        }

        public bool HasConfigurationKey(string key)
        {
            return _configuration.GetSection(key).Exists();
        }

        public IConfigurationSection GetConfigurationSection(string sectionName)
        {
            return _configuration.GetSection(sectionName);
        }

        public void ValidateConfiguration()
        {
            var requiredSections = new[] { "Framework", "Modules", "Security", "Network", "Output" };

            foreach (var section in requiredSections)
            {
                if (!_configuration.GetSection(section).Exists())
                {
                    throw new InvalidOperationException($"Required configuration section '{section}' is missing");
                }
            }

            if (MaxThreads <= 0 || MaxThreads > 100)
            {
                throw new InvalidOperationException("MaxThreads must be between 1 and 100");
            }

            if (DefaultTimeout <= 0)
            {
                throw new InvalidOperationException("DefaultTimeout must be greater than 0");
            }

            if (StealthDelay < 0)
            {
                throw new InvalidOperationException("StealthDelay cannot be negative");
            }
        }

        private string ToPascalCase(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return char.ToUpperInvariant(input[0]) + input.Substring(1).ToLowerInvariant();
        }
    }
}