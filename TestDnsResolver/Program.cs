using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TestDnsResolver
{
    class Program
    {
        static void Main(string[] args)
        {
            GFWDnsResolver dnsResolver = GFWDnsResolver.Instance();
            string domain = "www.goagentplus.com";
            string ip = dnsResolver.GFWResolve(domain);
            Console.WriteLine(ip + "    " + domain);
            Console.ReadKey();
        }
    }

    public class GFWDnsResolver
    {
        private static GFWDnsResolver resolver = null;
        
        private static string DNS_SERVER = "8.8.8.8";

        private Encoding coding = Encoding.UTF8;

        private bool debug = false;
        private bool cache = false;

        private int maxTryTimes = 2;
        private int waitTimes = 3;

        private Dictionary<string, string> dnsCache = new Dictionary<string, string>();

        string[] blackList = {
			"74.125.127.102", "74.125.155.102", "74.125.39.102", "74.125.39.113",
			 "209.85.229.138",
			 "128.121.126.139", "159.106.121.75", "169.132.13.103", "192.67.198.6",
			 "202.106.1.2", "202.181.7.85", "203.161.230.171", "203.98.7.65",
			 "207.12.88.98", "208.56.31.43", "209.145.54.50", "209.220.30.174",
			 "209.36.73.33", "211.94.66.147", "213.169.251.35", "216.221.188.182", 
			 "216.234.179.13", "243.185.187.39", "37.61.54.158", "4.36.66.178",
			 "46.82.174.68", "59.24.3.173", "64.33.88.161", "64.33.99.47",
			 "64.66.163.251", "65.104.202.252", "65.160.219.113", "66.45.252.237",                                                                                                                           
			 "72.14.205.104", "72.14.205.99", "78.16.49.15", "8.7.198.45", "93.46.8.89"};

        public static GFWDnsResolver Instance()
        {
            if (resolver == null)
            {
                resolver = new GFWDnsResolver();
            }
            return resolver;
        }

        private GFWDnsResolver() { }

        private bool IsBadReply(string ip)
        {
            for (int i = 0; i < blackList.Length; i++)
            {
                if (blackList[i].Equals(ip))
                {
                    return true;
                }
            }
            return false;
        }

        public string GFWResolve(string domain)
        {
            IPAddress[] address = Dns.GetHostAddresses(domain);
            string ip = address[0].ToString();
            if (!IsBadReply(ip))
            {
                return ip;
            }
            else if (cache && dnsCache.ContainsKey(domain))
            {
                return dnsCache[domain];
            }

            for (int i = 0; i < maxTryTimes; i++)
            {
                ip = Resolve(domain);
                if (IsBadReply(ip) || ip == null)
                {
                    continue;
                }
                else
                {
                    if (cache)
                    {
                        dnsCache.Add(domain, ip);
                    }
                    return ip;
                }
            }
            return string.Empty;
        }

        private void HexDump(byte[] bytes)
        {
            Console.WriteLine(BytesToHex(bytes));
        }

        private string BytesToHex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.AppendFormat("{0:X2}", bytes[i]);
            }

            string hex = sb.ToString();
            return hex;
        }

        private string Resolve(string domain)
        {
            byte[] recvData = new byte[512];
            byte[] data = BuildRequestData(domain);
            string result = null;
            if (debug)
            {
                Console.WriteLine(" =============== dns query request package dump: ================");
                HexDump(data);
            }

            IPEndPoint iep = new IPEndPoint(IPAddress.Parse(DNS_SERVER), 53);
            Socket dataSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            dataSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 6 * 1000);
            dataSocket.SendTo(data, iep);

            byte[] respData = new byte[512];
            for (int i = 0; i < waitTimes; i++)
            {
                try
                {
                    int intReceived = dataSocket.Receive(respData);
                    byte[] dataReceive = new byte[intReceived];
                    Array.Copy(respData, dataReceive, intReceived);

                    if (debug)
                    {
                        Console.WriteLine("============ dns query answer package dump");
                        HexDump(dataReceive);
                    }

                    string ip = DecodeDnsResponse(dataReceive, domain);
                    if (IsBadReply(ip))
                    {
                        continue;
                    }
                    else
                    {
                        result = ip;
                        break;
                    }
                }
                catch (SocketException ex)
                {
                    throw ex;
                }
            }

            dataSocket.Close();
            return result;
        }

        private byte[] BuildRequestData(string host)
        {
            // head + (host length +1) + eof sign + qtype + qclass
            int size = 12 + host.Length + 1 + 1 + 4;
            using (MemoryStream buff = new MemoryStream(size))
            {
                byte[] tmp = null;

                Random random = new Random();
                byte[] seq = new byte[2];
                random.NextBytes(seq);
                buff.Write(seq, 0, seq.Length);

                byte[] header = new byte[] { 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                buff.Write(header, 0, header.Length);

                string[] parts = host.Split('.');
                for (int i = 0; i < parts.Length; i++)
                {
                    buff.WriteByte((byte)parts[i].Length);

                    byte[] partsByte = coding.GetBytes(parts[i]);
                    buff.Write(partsByte, 0, partsByte.Length);
                }

                tmp = new byte[] { 0x00 };
                buff.Write(tmp, 0, tmp.Length);

                tmp = new byte[] { 0x00, 0x01, 0x00, 0x01 };
                buff.Write(tmp, 0, tmp.Length);

                return buff.ToArray();
            }
        }

        private string DecodeDnsResponse(byte[] resp, string host)
        {
            using (MemoryStream stream = new MemoryStream(resp))
            {
                using (BinaryReader buffer = new BinaryReader(stream))
                {
                    //parse the query answer count.
                    int pos = 7;
                    stream.Position = pos;
                    ushort qncount = buffer.ReadUInt16();

                    //skip query answer field
                    pos = 12 + 1 + host.Length + 1 + 4;
                    stream.Position = pos;
                    for (int i = 0; i < qncount; i++)
                    {
                        stream.Position = pos;
                        byte pointFlg = buffer.ReadByte();
                        if ((pointFlg & 0xc0) == 0xc0)
                        {
                            pos += 3;
                        }
                        else
                        {
                            pos += 2 + host.Length + 1;
                        }

                        stream.Position = pos;
                        ushort queryType = buffer.ReadUInt16();

                        if (debug)
                        {
                            Console.WriteLine("qncount:" + qncount + "pos:" + pos + "queryType:" + queryType);
                        }

                        pos += 8;
                        stream.Position = pos;
                        int dataLen = buffer.ReadByte();
                        pos += 1; 

                        //A record
                        if (queryType == 0x0001)
                        {
                            if (debug)
                            {
                                Console.WriteLine("parse A record");
                            }

                            string ip = string.Empty;
                            for (int j = 0; j < dataLen; j++)
                            {
                                stream.Position = pos;
                                int v = buffer.ReadByte();
                                v = v > 0 ? v : 0x0ff & v;
                                ip += v + (j == dataLen - 1 ? "" : ".");
                                pos += 1;
                            }
                            return ip;
                        }
                        else
                        {
                            pos += dataLen;
                        }
                    }
                    return string.Empty;
                }            
            }
        }
    }
}
