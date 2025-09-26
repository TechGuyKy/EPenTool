using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using EPenT.Models.System;

namespace EPenT.Modules.Reconnaissance
{
    public class NetworkScanner
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<NetworkScanner> _logger;
        private readonly List<int> _defaultPorts;
        private readonly int _scanTimeout;
        private readonly int _maxConcurrentScans;

        public NetworkScanner(IConfiguration configuration, ILogger<NetworkScanner> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _defaultPorts = GetDefaultPorts();
            _scanTimeout = _configuration.GetValue<int>("Network:ScanTimeout", 5000);
            _maxConcurrentScans = _configuration.GetValue<int>("Network:MaxConcurrentScans", 50);
        }

        public async Task<NetworkInformation> ScanNetworkAsync()
        {
            var networkInfo = new NetworkInformation
            {
                LocalIPAddresses = GetLocalIPAddresses(),
                DiscoveredHosts = new List<string>(),
                OpenPorts = new Dictionary<string, List<int>>(),
                NetworkInterfaces = GetNetworkInterfaces()
            };

            try
            {
                _logger.LogInformation("Starting network discovery");

                var localNetworks = GetLocalNetworks(networkInfo.LocalIPAddresses);

                foreach (var network in localNetworks)
                {
                    var hosts = await DiscoverHostsAsync(network);
                    networkInfo.DiscoveredHosts.AddRange(hosts);
                }

                if (_configuration.GetValue<bool>("Network:EnablePortScan", true))
                {
                    _logger.LogInformation("Starting port scanning");
                    await ScanPortsAsync(networkInfo);
                }

                _logger.LogInformation($"Network scan completed. Found {networkInfo.DiscoveredHosts.Count} hosts");
                return networkInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Network scanning failed");
                return networkInfo;
            }
        }

        private async Task<List<string>> DiscoverHostsAsync(string networkRange)
        {
            var hosts = new List<string>();
            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(_maxConcurrentScans);

            try
            {
                var baseIP = networkRange.Split('/')[0];
                var ipBytes = IPAddress.Parse(baseIP).GetAddressBytes();

                for (int i = 1; i < 255; i++)
                {
                    var targetIP = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.{i}";

                    tasks.Add(Task.Run(async () =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {
                            if (await PingHostAsync(targetIP))
                            {
                                lock (hosts)
                                {
                                    hosts.Add(targetIP);
                                }
                                _logger.LogDebug($"Host discovered: {targetIP}");
                            }
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }));
                }

                await Task.WhenAll(tasks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Host discovery failed for network: {networkRange}");
            }

            return hosts;
        }

        private async Task<bool> PingHostAsync(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, _scanTimeout);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        private async Task ScanPortsAsync(NetworkInformation networkInfo)
        {
            var allHosts = new List<string>(networkInfo.DiscoveredHosts);
            allHosts.AddRange(networkInfo.LocalIPAddresses);

            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(_maxConcurrentScans);

            foreach (var host in allHosts.Distinct())
            {
                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        var openPorts = await ScanHostPortsAsync(host);
                        if (openPorts.Any())
                        {
                            lock (networkInfo.OpenPorts)
                            {
                                networkInfo.OpenPorts[host] = openPorts;
                            }
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
        }

        private async Task<List<int>> ScanHostPortsAsync(string host)
        {
            var openPorts = new List<int>();
            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(10);

            foreach (var port in _defaultPorts)
            {
                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        if (await IsPortOpenAsync(host, port))
                        {
                            lock (openPorts)
                            {
                                openPorts.Add(port);
                            }
                            _logger.LogDebug($"Open port found: {host}:{port}");
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
            return openPorts;
        }

        private async Task<bool> IsPortOpenAsync(string host, int port)
        {
            try
            {
                using var tcpClient = new TcpClient();
                var connectTask = tcpClient.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(_scanTimeout);

                var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                if (completedTask == connectTask && !connectTask.IsFaulted)
                {
                    return tcpClient.Connected;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private List<string> GetLocalIPAddresses()
        {
            var addresses = new List<string>();

            try
            {
                var hostEntry = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var address in hostEntry.AddressList)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(address))
                    {
                        addresses.Add(address.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get local IP addresses");
            }

            return addresses;
        }

        private List<string> GetLocalNetworks(List<string> localIPs)
        {
            var networks = new List<string>();

            foreach (var ip in localIPs)
            {
                try
                {
                    var ipBytes = IPAddress.Parse(ip).GetAddressBytes();
                    var networkBase = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.0/24";

                    if (!networks.Contains(networkBase))
                    {
                        networks.Add(networkBase);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Failed to determine network for IP: {ip}");
                }
            }

            return networks;
        }

        private List<string> GetNetworkInterfaces()
        {
            var interfaces = new List<string>();

            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var description = $"{ni.Name} ({ni.NetworkInterfaceType}) - {ni.OperationalStatus}";
                        interfaces.Add(description);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate network interfaces");
            }

            return interfaces;
        }

        private List<int> GetDefaultPorts()
        {
            var ports = new List<int>();
            var configPorts = _configuration.GetSection("Network:DefaultPorts").Get<int[]>();

            if (configPorts != null && configPorts.Length > 0)
            {
                ports.AddRange(configPorts);
            }
            else
            {
                ports.AddRange(new int[]
                {
                    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 8080, 8443
                });
            }

            return ports;
        }
    }
}