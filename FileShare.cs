using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using NetFwTypeLib;
using System.Text;
using System.Data;

namespace FileShare
{
    internal class FileTransmission
    {
        public static async Task Send(string filePath, string ipAddress, int port)
        {
            await Task.Run(() => {
                try
                {
                    // Open the file and get its length
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    {
                        string fileName = Path.GetFileName(filePath);
                        long fileLength = fs.Length;

                        Console.WriteLine($"Attempting to send file {fileName} to IP: {ipAddress} PORT: {port}");

                        // Create a TcpClient
                        TcpClient client = new TcpClient(ipAddress, port);
                        Console.WriteLine($"Client created ...");

                        // Get a client stream for reading and writing
                        NetworkStream stream = client.GetStream();
                        Console.WriteLine($"Stream initialized ...");

                        // Send information about the file to the remote device
                        byte[] fileNameBytes = Encoding.UTF8.GetBytes(fileName);
                        byte[] fileNameLengthBytes = BitConverter.GetBytes(fileNameBytes.Length);
                        byte[] fileLengthBytes = BitConverter.GetBytes(fileLength);

                        stream.Write(fileNameLengthBytes, 0, fileNameLengthBytes.Length);
                        stream.Write(fileNameBytes, 0, fileNameBytes.Length);
                        stream.Write(fileLengthBytes, 0, fileLengthBytes.Length);

                        // Send the file to the remote device
                        byte[] fileBuffer = new byte[client.SendBufferSize];
                        int bytesRead;
                        long totalBytesRead = 0;
                        Console.ForegroundColor = ConsoleColor.Green;
                        while ((bytesRead = fs.Read(fileBuffer, 0, fileBuffer.Length)) != 0)
                        {
                            stream.Write(fileBuffer, 0, bytesRead);
                            totalBytesRead += bytesRead;
                            Console.WriteLine($"Progress: {(double)totalBytesRead / fileLength * 100:F2}%");
                        }

                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"File {fileName} sent successfully!");

                        // Close everything
                        stream.Close();
                        client.Close();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                }
            });
        }
        public static async Task Receive(string savePath, int port)
        {
            await Task.Run(() =>
            {
                try
                {
                    // Create a TcpListener
                    TcpListener listener = new TcpListener(IPAddress.Any, port);
                    listener.Start();
                    Console.WriteLine("Listening...");

                    // Wait for a client to connect
                    TcpClient client = listener.AcceptTcpClient();
                    Console.WriteLine("Client connected...");

                    // Get a client stream for reading
                    NetworkStream stream = client.GetStream();

                    // Receive information about the file
                    byte[] fileNameLengthBytes = new byte[4];
                    stream.Read(fileNameLengthBytes, 0, fileNameLengthBytes.Length);
                    int fileNameLength = BitConverter.ToInt32(fileNameLengthBytes, 0);

                    byte[] fileNameBytes = new byte[fileNameLength];
                    stream.Read(fileNameBytes, 0, fileNameBytes.Length);
                    string fileName = Encoding.UTF8.GetString(fileNameBytes);

                    byte[] fileLengthBytes = new byte[8];
                    stream.Read(fileLengthBytes, 0, fileLengthBytes.Length);
                    long fileLength = BitConverter.ToInt64(fileLengthBytes, 0);

                    Console.WriteLine($"Receiving file: {fileName}, size: {fileLength} bytes");
                    Console.ForegroundColor = ConsoleColor.Green;
                    // Receive the file from the remote device
                    using (FileStream fs = new FileStream(Path.Combine(savePath, fileName), FileMode.Create, FileAccess.Write))
                    {
                        byte[] fileBuffer = new byte[client.ReceiveBufferSize];
                        int bytesRead;
                        long totalBytesRead = 0;
                        while ((bytesRead = stream.Read(fileBuffer, 0, fileBuffer.Length)) != 0)
                        {
                            fs.Write(fileBuffer, 0, bytesRead);
                            totalBytesRead += bytesRead;
                            Console.WriteLine($"Progress: {(double)totalBytesRead / fileLength * 100:F2}%");
                        }
                    }

                    Console.WriteLine("File received successfully!");

                    // Close everything
                    stream.Close();
                    client.Close();
                    listener.Stop();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                }

            });
        }
    }

    internal class Connection {
        public static bool AssignPrivillages() {
            try {
                // Set up permissions to allow access to the port
                string ruleName = string.Format("Allow Port {0}", 8080);
                string programPath = Environment.ProcessPath;

                // Create a new rule with the specified name and program path
                NetFwTypeLib.INetFwRule rule = (NetFwTypeLib.INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));

                rule.Name = ruleName;
                rule.ApplicationName = programPath;
                rule.Protocol = (int)NetFwTypeLib.NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                rule.LocalPorts = "8080";
                rule.Enabled = true;
                rule.Action = NetFwTypeLib.NET_FW_ACTION_.NET_FW_ACTION_ALLOW;

                // Get the Windows Firewall policy
                Type firewallPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(firewallPolicyType);

                // Add the rule to the policy
                firewallPolicy.Rules.Add(rule);
                return true;
            } catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return false;
            }
            
        }
    }
}
