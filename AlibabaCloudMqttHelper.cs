using System;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp
{
    public class AlibabaCloudMqttHelper
    {
        public static MqttClientcredentials CreateClientCredentials(string productKey, string deviceName, string deviceSecret)
        {
            productKey = productKey ?? throw new ArgumentNullException(nameof(productKey));
            deviceName = deviceName ?? throw new ArgumentNullException(nameof(deviceName));
            deviceSecret = deviceSecret ?? throw new ArgumentNullException(nameof(deviceSecret));

            string userName = $"{deviceName}&{productKey}";

            long timestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds();

            string plainPwd = $"clientId{productKey}.{deviceName}{nameof(deviceName)}{deviceName}{nameof(productKey)}{productKey}{nameof(timestamp)}{timestamp}";

            string password = HmacSha256(plainPwd, deviceSecret);

            string clientId = $"{productKey}.{deviceName}|securemode=2,signmethod=hmacsha256,{nameof(timestamp)}={timestamp}|";

            return new MqttClientcredentials(userName, password, clientId);
        }

        public class MqttClientcredentials
        {
            public string UserName { get; }

            public string Password { get; }

            public string ClientId { get; }

            public MqttClientcredentials(string userName, string password, string clientId)
            {
                UserName = userName;
                Password = password;
                ClientId = clientId;
            }
        }

        public static string HmacSha256(string plainText, string key)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            HMACSHA256 hmac = new HMACSHA256(keyBytes);

            byte[] sign = hmac.ComputeHash(plainTextBytes);

            return BitConverter.ToString(sign).Replace("-", string.Empty);
        }
    }
}
