using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Commandline;
using EPenT.Core;
using System.Runtime.InteropServices;

namespace EPenT
{
    public class Program
    {
        private static ILogger<Program>? _logger;
        private static IConfiguration? _configuration;
        private static PentestFramework? _framework;

        public class Options
        {
            [Option('t', "target", Required = false, HelpText = "Target IP address or hostname")]
            public string? Target { get; set; }

            [Option('m', "modules", Required = false, HelpText = "Comma-separated list of modules to run (recon,exploit,persist,etc.)")]
            public string? Modules { get; set; }

            [Option('o', "output", Required = false, HelpText = "Output directory for reports and logs")]
            public string? OutputPath { get; set; }

            [Option('v', "verbose", Required = false, HelpText = "Enable verbose logging")]
            public bool Verbose { get; set; }

            [Option('s', "stealth", Required = false, HelpText = "Enable stealth mode (slower but more evasive)")]
            public bool StealthMode { get; set; }

            [Option('r', "report", Required = false, HelpText = "Report format (html,json,csv,pdf)", Default = "html")]
            public string ReportFormat { get; set; } = "html";

            [Option('c', "config", Required = false, HelpText = "Custom configuration file path")]
            public string? ConfigPath { get; set; }

            [Option("no-banner", Required = false, HelpText = "Suppress banner display")]
            public bool NoBanner { get; set; }

            [Option("dry-run", Required = false, HelpText = "Perform dry run without executing exploits")]
            public bool DryRun { get; set; }
        }

        public static async Task<int> Main(string[] args)
        {
            try
            {
                var parseResult = Parser.Default.ParseArguments<Options>(args);

                return await parseResult.MapResult(
                    async (Options opts) => await RunApplication(opts),
                    errors => Task.FromResult(HandleParseError(errors))
                );
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[FATAL] Unhandled exception: {ex.Message}");
                Console.ResetColor();

                if (_logger != null)
                {
                    _logger.LogCritical(ex, "Unhandled exception occurred");
                }

                return -1;
            }
        }

        private static async Task<int> RunApplication(Options options)
        {
            try
            {
                if (!IsRunAsAdministrator())
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[WARNING] Not running as administrator. Some features may be limited.");
                    Console.ResetColor();
                }

                if (!options.NoBanner)
                {
                    DisplayBanner();
                }

                await InitializeConfiguration(options);
                await InitializeLogging(options);

                _logger?.LogInformation("Elite Windows Pentest Suite starting up...");
                _logger?.LogInformation($"Version: {GetVersion()}");
                _logger?.LogInformation($"Runtime: {Environment.Version}");
                _logger?.LogInformation($"Platform: {Environment.OSVersion}");

                if (!ValidateEnvironment())
                {
                    _logger?.LogError("Environment validation failed");
                    return -2;
                }

                _framework = new PentestFramework(_configuration!, _logger!);
                await ConfigureFramework(options);
                DisplayExecutionSummary(options);

                _logger?.LogInformation("Starting penetration test assessment...");

                var results = await _framework.ExecuteAssessment();

                _logger?.LogInformation("Generating assessment reports...");
                await _framework.GenerateReports(results, options.ReportFormat);

                DisplayCompletionSummary(results);

                _logger?.LogInformation("Assessment completed successfully");
                return 0;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Application execution failed: {ex.Message}");
                Console.ResetColor();

                _logger?.LogError(ex, "Application execution failed");
                return -3;
            }
        }

        private static void DisplayBanner()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ███████╗██╗     ██╗████████╗███████╗    ██████╗ ███████╗███╗   ██╗████████╗║
║    ██╔════╝██║     ██║╚══██╔══╝██╔════╝    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝║
║    █████╗  ██║     ██║   ██║   █████╗      ██████╔╝█████╗  ██╔██╗ ██║   ██║   ║
║    ██╔══╝  ██║     ██║   ██║   ██╔══╝      ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ║
║    ███████╗███████╗██║   ██║   ███████╗    ██║     ███████╗██║ ╚████║   ██║   ║
║    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ║
║                                                                               ║
║              ██╗    ██╗██╗███╗   ██╗██████╗  ██████╗ ██╗    ██╗███████╗       ║
║              ██║    ██║██║████╗  ██║██╔══██╗██╔═══██╗██║    ██║██╔════╝       ║
║              ██║ █╗ ██║██║██╔██╗ ██║██║  ██║██║   ██║██║ █╗ ██║███████╗       ║
║              ██║███╗██║██║██║╚██╗██║██║  ██║██║   ██║██║███╗██║╚════██║       ║
║              ╚███╔███╔╝██║██║ ╚████║██████╔╝╚██████╔╝╚███╔███╔╝███████║       ║
║               ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝       ║
║                                                                               ║
║                    ╔═══════════════════════════════════════╗                 ║
║                    ║     PENETRATION TESTING SUITE        ║                 ║
║                    ║         Educational Framework        ║                 ║
║                    ╚═══════════════════════════════════════╝                 ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"║  Version: {GetVersion(),-25} Build: {GetBuildDate(),-25}  ║");
            Console.WriteLine("║  Author:  Elite Security Research    Target: Windows Environments  ║");
            Console.WriteLine("║  Purpose: Educational & Authorized Testing Only                     ║");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("⚠️  LEGAL NOTICE: This tool is for educational purposes and authorized");
            Console.WriteLine("   penetration testing only. Unauthorized use is strictly prohibited.");
            Console.WriteLine("   Users are responsible for compliance with applicable laws.");
            Console.ResetColor();
            Console.WriteLine();

            Task.Delay(2000).Wait();
        }

        private static async Task InitializeConfiguration(Options options)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

            if (!string.IsNullOrEmpty(options.ConfigPath) && File.Exists(options.ConfigPath))
            {
                builder.AddJsonFile(options.ConfigPath, optional: true, reloadOnChange: true);
            }

            _configuration = builder.Build();
            await Task.CompletedTask;
        }

        private static async Task InitializeLogging(Options options)
        {
            var services = new ServiceCollection();

            services.AddLogging(builder =>
            {
                builder.ClearProviders();
                builder.AddConsole();

                if (options.Verbose)
                {
                    builder.SetMinimumLevel(LogLevel.Debug);
                }
                else
                {
                    builder.SetMinimumLevel(LogLevel.Information);
                }
            });

            var serviceProvider = services.BuildServiceProvider();
            _logger = serviceProvider.GetRequiredService<ILogger<Program>>();

            await Task.CompletedTask;
        }

        private static async Task ConfigureFramework(Options options)
        {
            if (_framework == null) return;

            if (!string.IsNullOrEmpty(options.Target))
            {
                _framework.SetTarget(options.Target);
            }

            if (!string.IsNullOrEmpty(options.Modules))
            {
                var modules = options.Modules.Split(',', StringSplitOptions.RemoveEmptyEntries);
                _framework.SetEnabledModules(modules);
            }

            if (!string.IsNullOrEmpty(options.OutputPath))
            {
                _framework.SetOutputPath(options.OutputPath);
            }

            if (options.StealthMode)
            {
                _framework.EnableStealthMode();
            }

            if (options.DryRun)
            {
                _framework.EnableDryRun();
            }

            await Task.CompletedTask;
        }

        private static bool ValidateEnvironment()
        {
            if (!Environment.OSVersion.Platform.ToString().Contains("Win"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] This tool requires Windows operating system");
                Console.ResetColor();
                return false;
            }

            if (Environment.Version.Major < 8)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] This tool requires .NET 8.0 or higher");
                Console.ResetColor();
                return false;
            }

            return true;
        }

        private static void DisplayExecutionSummary(Options options)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("╔═══════════════════════════════════════╗");
            Console.WriteLine("║          EXECUTION SUMMARY            ║");
            Console.WriteLine("╠═══════════════════════════════════════╣");
            Console.ResetColor();

            Console.WriteLine($"║ Target:       {options.Target ?? "localhost",-23} ║");
            Console.WriteLine($"║ Modules:      {options.Modules ?? "all",-23} ║");
            Console.WriteLine($"║ Report:       {options.ReportFormat,-23} ║");
            Console.WriteLine($"║ Stealth:      {(options.StealthMode ? "enabled" : "disabled"),-23} ║");
            Console.WriteLine($"║ Dry Run:      {(options.DryRun ? "enabled" : "disabled"),-23} ║");
            Console.WriteLine($"║ Admin Mode:   {(IsRunAsAdministrator() ? "yes" : "no"),-23} ║");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("╚═══════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();
        }

        private static void DisplayCompletionSummary(object results)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("╔═══════════════════════════════════════╗");
            Console.WriteLine("║         ASSESSMENT COMPLETE          ║");
            Console.WriteLine("╠═══════════════════════════════════════╣");
            Console.WriteLine("║ Status:       SUCCESS                ║");
            Console.WriteLine("║ Duration:     [Calculated at runtime]║");
            Console.WriteLine("║ Findings:     [To be implemented]    ║");
            Console.WriteLine("║ Reports:      Generated successfully  ║");
            Console.WriteLine("╚═══════════════════════════════════════╝");
            Console.ResetColor();

            Console.WriteLine();
            Console.WriteLine("📊 Check the Output directory for detailed reports and logs.");
            Console.WriteLine("🔍 Review findings carefully and verify all results.");
            Console.WriteLine("⚠️  Ensure proper authorization before using findings.");
        }

        private static bool IsRunAsAdministrator()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static int HandleParseError(IEnumerable<object> errors)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] Invalid command line arguments");
            Console.ResetColor();
            return -1;
        }

        private static string GetVersion()
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            return version?.ToString() ?? "1.0.0.0";
        }

        private static string GetBuildDate()
        {
            var buildDate = File.GetCreationTime(Assembly.GetExecutingAssembly().Location);
            return buildDate.ToString("yyyy-MM-dd");
        }
    }
}