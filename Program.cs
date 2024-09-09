using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;
using Whois.NET;

class Program
{
    private static readonly Dictionary<int, string> portServices = new Dictionary<int, string>()
    {
        { 20, "FTP Data Transfer" }, { 21, "FTP Control" }, { 22, "SSH" }, { 23, "Telnet" }, { 25, "SMTP" },
        { 53, "DNS" }, { 67, "DHCP Server" }, { 68, "DHCP Client" }, { 69, "TFTP" }, { 80, "HTTP" },
        { 110, "POP3" }, { 123, "NTP" }, { 137, "NetBIOS Name Service" }, { 138, "NetBIOS Datagram Service" },
        { 139, "NetBIOS Session Service" }, { 143, "IMAP" }, { 161, "SNMP" }, { 162, "SNMP Trap" },
        { 179, "BGP" }, { 389, "LDAP" }, { 443, "HTTPS" }, { 465, "SMTPS" }, { 500, "ISAKMP" },
        { 514, "Syslog" }, { 520, "RIP" }, { 546, "DHCPv6 Client" }, { 547, "DHCPv6 Server" }, { 587, "SMTP" },
        { 636, "LDAPS" }, { 989, "FTPS Data" }, { 990, "FTPS Control" }, { 993, "IMAPS" }, { 995, "POP3S" },
        { 1025, "Microsoft RPC" }, { 1080, "SOCKS Proxy" }, { 1194, "OpenVPN" }, { 1433, "Microsoft SQL Server" },
        { 1701, "L2TP" }, { 1723, "PPTP" }, { 1812, "RADIUS Authentication" }, { 1813, "RADIUS Accounting" },
        { 2082, "cPanel" }, { 2083, "cPanel over SSL" }, { 2086, "WHM (Webhost Manager)" },
        { 2087, "WHM (Webhost Manager) over SSL" }, { 2095, "Webmail" }, { 2096, "Webmail over SSL" },
        { 2483, "Oracle Database" }, { 2484, "Oracle Database" }, { 3306, "MySQL" }, { 3389, "Remote Desktop" },
        { 5060, "SIP" }, { 5061, "SIP over TLS" }, { 5432, "PostgreSQL" }, { 5900, "VNC" }, { 6001, "X11" },
        { 8008, "HTTP Alternate" }, { 8080, "HTTP-Proxy" }, { 8443, "Plesk Control Panel" }, { 8888, "News Server" },
        { 27017, "MongoDB" }
    };

    static async Task Main(string[] args)
    {
        Console.Write("Enter domain names (comma separated): ");
        string[] domainNames = Console.ReadLine().Split(',');

        Console.Write("Scan all ports or common ports for all domains? (all/common): ");
        string scanOption = Console.ReadLine().ToLower();
        IEnumerable<int> ports;

        switch (scanOption)
        {
            case "all":
                ports = Enumerable.Range(1, 65535);
                break;
            case "common":
                ports = Enumerable.Range(1, 1024);
                break;
            default:
                Console.WriteLine("Invalid option. Exiting...");
                return;
        }

        foreach (var domainName in domainNames)
        {
            var trimmedDomain = domainName.Trim();
            var ip = GetIpAddress(trimmedDomain);

            Console.WriteLine($"\nScanning {trimmedDomain} ({ip})");

            var serverSoftware = await GetServerSoftware(trimmedDomain);
            Console.WriteLine($"\nServer Software for {trimmedDomain}: {serverSoftware}");

            var dnsRecords = GetDnsRecords(trimmedDomain);
            Console.WriteLine($"\nDNS Records for {trimmedDomain}:");
            foreach (var record in dnsRecords)
            {
                Console.WriteLine($"{record.Key}: {string.Join(", ", record.Value)}");
            }

            var subdomains = FindSubdomains(trimmedDomain);
            Console.WriteLine($"\nSubdomains for {trimmedDomain}: {string.Join(", ", subdomains)}");

            var whoisInfo = GetWhoisInfo(trimmedDomain);
            if (whoisInfo != null)
            {
                Console.WriteLine($"\nWhois information for {trimmedDomain}:");
                Console.WriteLine(whoisInfo.Raw);
            }

            var sslInfo = await GetSslCertInfo(trimmedDomain);
            if (sslInfo != null)
            {
                Console.WriteLine($"\nSSL Certificate Issuer for {trimmedDomain}:");
                Console.WriteLine($"Issuer: {sslInfo.Issuer}");
                Console.WriteLine($"Subject: {sslInfo.Subject}");
            }

            var openPorts = await ScanPorts(ports, ip);
            Console.WriteLine($"\nSummary for {trimmedDomain}:");
            foreach (var port in openPorts)
            {
                portServices.TryGetValue(port, out string service);
                Console.WriteLine($"Port {port} is open ({service ?? "Unknown service"})");
            }
        }

        Console.WriteLine("\nScanning complete.");
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    static string GetIpAddress(string domainName)
    {
        try
        {
            return Dns.GetHostAddresses(domainName).FirstOrDefault()?.ToString();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error resolving IP address for {domainName}: {ex.Message}");
            return string.Empty;
        }
    }

    static async Task<string> GetServerSoftware(string domainName)
    {
        try
        {
            using (var client = new HttpClient())
            {
                var response = await client.GetAsync($"http://{domainName}");
                return response.Headers.Server.ToString();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not retrieve server software for {domainName}: {ex.Message}");
            return "Unknown";
        }
    }

    static Dictionary<string, List<string>> GetDnsRecords(string domainName)
    {
        var lookup = new LookupClient();
        var records = new Dictionary<string, List<string>>();
        var recordTypes = new[] { "A", "CNAME", "MX", "NS", "SOA" };

        foreach (var recordType in recordTypes)
        {
            try
            {
                var query = lookup.Query(domainName, QueryTypeFromString(recordType));
                records[recordType] = query.Answers.Select(a => a.ToString()).ToList();
            }
            catch
            {
                // Ignore any errors for now
            }
        }

        return records;
    }

    static IEnumerable<string> FindSubdomains(string domainName)
    {
        var subdomains = new[]
        {
            "www", "mail", "ftp", "webmail", "smtp", "dev", "admin", "portal", "blog", "vpn",
            "shop", "api", "cdn", "test", "mx", "pop", "imap", "cpanel", "whm", "webdisk", "webmin",
            "support", "forum", "direct", "demo", "beta", "alpha", "autodiscover", "autoconfig",
            "secure", "public", "private", "staging", "store", "login", "signup", "account", "billing"
        };
        var foundSubdomains = new List<string>();

        foreach (var subdomain in subdomains)
        {
            try
            {
                var result = Dns.GetHostAddresses($"{subdomain}.{domainName}");
                foundSubdomains.Add(subdomain);
            }
            catch
            {
                // Ignore DNS resolution failures
            }
        }

        return foundSubdomains;
    }

    static WhoisResponse GetWhoisInfo(string domainName)
    {
        try
        {
            var whoisResponse = WhoisClient.Query(domainName);
            return whoisResponse;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not retrieve whois information for {domainName}: {ex.Message}");
            return null;
        }
    }

    static async Task<X509Certificate2> GetSslCertInfo(string domainName)
    {
        try
        {
            using (var client = new TcpClient())
            {
                var connectTask = client.ConnectAsync(domainName, 443);
                var connectTimeoutTask = Task.Delay(5000); // 5-second timeout

                if (await Task.WhenAny(connectTask, connectTimeoutTask) == connectTimeoutTask)
                {
                    Console.WriteLine($"Connection to {domainName} timed out.");
                    return null;
                }

                using (var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) => true))
                {
                    var authTask = sslStream.AuthenticateAsClientAsync(domainName);
                    var authTimeoutTask = Task.Delay(5000); // 5-second timeout for SSL handshake

                    if (await Task.WhenAny(authTask, authTimeoutTask) == authTimeoutTask)
                    {
                        Console.WriteLine($"SSL authentication with {domainName} timed out.");
                        return null;
                    }

                    var cert = new X509Certificate2(sslStream.RemoteCertificate);
                    return cert;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not retrieve SSL certificate information for {domainName}: {ex.Message}");
            return null;
        }
    }

    static async Task<List<int>> ScanPorts(IEnumerable<int> ports, string ip)
    {
        var openPorts = new List<int>();

        using (var semaphore = new SemaphoreSlim(5000))
        {
            var tasks = ports.Select(async port =>
            {
                await semaphore.WaitAsync();

                try
                {
                    using (var client = new TcpClient())
                    {
                        var connectTask = client.ConnectAsync(ip, port);
                        var timeoutTask = Task.Delay(5000); // 5-second timeout

                        if (await Task.WhenAny(connectTask, timeoutTask) == timeoutTask)
                        {
                            // Timeout occurred, assume port is closed
                            return;
                        }

                        if (client.Connected)
                        {
                            openPorts.Add(port);
                            Console.WriteLine($"Port {port} is open on {ip}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Log the exception (optional)
                    Console.WriteLine($"Exception scanning port {port} on {ip}: {ex.Message}");
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
        }

        return openPorts;
    }


    static QueryType QueryTypeFromString(string recordType)
    {
        return recordType switch
        {
            "A" => QueryType.A,
            "CNAME" => QueryType.CNAME,
            "MX" => QueryType.MX,
            "NS" => QueryType.NS,
            "SOA" => QueryType.SOA,
            _ => QueryType.A,
        };
    }
}
