using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Text;

namespace Sharpbin
{
    public class Turnstile
    {
        public static async Task<bool> VerifyTurnstileToken(string token)
        {
            var httpClient = new HttpClient();
            JObject requestBody = new JObject
            {
                ["secret"] = Program.cfTurnstileSecret,
                ["response"] = token
            };
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("https://challenges.cloudflare.com/turnstile/v0/siteverify"),
                Content = new StringContent(requestBody.ToString(), Encoding.UTF8, "application/json")
            };
            using (var response = await httpClient.SendAsync(request))
            {
                var jsonresponse = JObject.Parse(await response.Content.ReadAsStringAsync());
                Console.WriteLine(jsonresponse["success"]?.ToString());
                if (jsonresponse["success"]?.ToString().ToLower() == "true")
                {
                    return true;
                }
                return false;
            }
        }
    }
}
