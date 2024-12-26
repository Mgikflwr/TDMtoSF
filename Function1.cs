using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Functions.Worker;
using Microsoft.AspNetCore.Http.HttpResults;
using System.Reflection.Metadata;


namespace TDMtoSF
{
    public class SnowflakeHandler
    {
        [Function("CallTDMPostorGet")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
             FunctionContext context)
        {
            var log = context.GetLogger("CallPostorGet");
            log.LogInformation("Azure Function CallPostorGet triggered.");

            try
            {
                //Handles Post Request
                if (req.Method == HttpMethods.Post)
                {
                    // Read request body (optional, in case input parameters are passed)
                    string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                    if (string.IsNullOrWhiteSpace(requestBody))
                    {
                        log.LogError("Request body is empty.");
                        return new BadRequestObjectResult("Request body is required and must contain valid JSON.");
                    }
                    var input = JsonSerializer.Deserialize<InputModel>(requestBody);
                    log.LogInformation($"Request body: {requestBody}");

                    // Default values or from request
                    string secretKey = input?.SecretKey ?? "b8a8a6189eac4a959c77f932b7ecafb7";
                    string sharedKey = input?.SharedKey ?? "4dda3de0dd964212b2c1d43e05e8c9eb";
                    string nepOrganization = input?.NepOrganization ?? "parkers-kitchen-prod";

                    // Call the POST method
                    var result = await CallPost(secretKey, sharedKey, nepOrganization, log);

                    if (string.IsNullOrWhiteSpace(result.Token))
                    {
                        log.LogError("Failed to retrieve token.");
                        return new StatusCodeResult(500);
                    }

                    // Return the token in the response
                    return new OkObjectResult(new
                    {
                        token = result.Token,
                        status = "Success"
                    });
                }
                else if (req.Method == HttpMethods.Get)
                {
                    // Handle GET requests
                    string secretKey = req.Query["secretKey"];
                    string sharedKey = req.Query["sharedKey"];
                    string nepOrganization = req.Query["nepOrganization"];

                    if (string.IsNullOrWhiteSpace(secretKey) || string.IsNullOrWhiteSpace(sharedKey) || string.IsNullOrWhiteSpace(nepOrganization))
                    {
                        return new BadRequestObjectResult("Missing query parameters: secretKey, sharedKey, or nepOrganization.");
                    }

                    var result = await CallGet(secretKey, sharedKey, nepOrganization, log);

                    if (result == null)
                    {
                        log.LogError("Failed to retrieve data for GET call.");
                        return new StatusCodeResult(500);
                    }

                    // Return the token in the response
                    return new OkObjectResult(new
                    {
                        rolename = result.RoleName,
                        token = result.Token,
                        status = result.StatusCode
                    });
                }
                else
                {
                    log.LogError("Unsupported HTTP method.");
                    return new BadRequestObjectResult("Unsupported HTTP method. Use POST or GET.");
                }
            }
            catch (HttpRequestException ex)
            {
                log.LogError($"HTTP request failed: {ex.Message}");
                return new StatusCodeResult(500);
            }
            catch (Exception ex)
            {
                log.LogError($"Unexpected error: {ex.Message}");
                return new StatusCodeResult(500);
            }
        }

        public static async Task<ApiResponse> CallPost(string secretKey, string sharedKey, string nepOrganization, ILogger log)
        {

            log.LogInformation($"Processing request for organization: {nepOrganization}");

            var utcDate = DateTime.UtcNow;
            var url = "https://api.ncr.com/security/authorization";
            var httpMethod = "POST";
            var contentType = "application/json";
            var hmacAccessKey = CreateHmac(sharedKey, secretKey, DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                httpMethod, url, contentType, "", "", "", nepOrganization, "");

            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, url);
            var gmtDate = utcDate.DayOfWeek.ToString().Substring(0, 3) + ", " +
                     utcDate.ToString("dd MMM yyyy HH:mm:ss") + " GMT";
            request.Headers.Add("nep-organization", nepOrganization);
            request.Headers.Add("date", gmtDate);
            request.Headers.Add("authorization", "AccessKey " + hmacAccessKey);

            var content = new StringContent(string.Empty, Encoding.UTF8, "application/json");
            content.Headers.Remove("Content-Type");
            content.Headers.Add("Content-Type", "application/json");
            request.Content = content;

            try
            {
                var response = await client.SendAsync(request);
                log.LogInformation("Request succeeded with status code {statusCode}.", response.StatusCode);
                var responseContentString = await response.Content.ReadAsStringAsync();

                var responseContent = JsonSerializer.Deserialize<ContentModel>(responseContentString);
                var options = new JsonSerializerOptions()
                {
                    WriteIndented = true
                };

                var formattedJson = JsonSerializer.Serialize(responseContent, options);
                return new ApiResponse
                {
                    Token = responseContent?.token,
                    StatusCode = (int)response.StatusCode
                };
                //Console.WriteLine("{ \"status\": " + response.StatusCode + " }\n" + formattedJson);
                //return (int)response.StatusCode;
            }
            catch (HttpRequestException ex)
            {
                log.LogError($"HTTP Request failed: {ex.Message}");
                throw;
            }
        }

        public static async Task<ApiResponse> CallGet(string secretKey, string sharedKey, string nepOrganization, ILogger log)
        {

            log.LogInformation($"Processing request for organization: {nepOrganization}");
            const string url = "https://api.ncr.com/security/role-grants/user-grants/self/effective-roles";
            const string httpMethod = "GET";
            const string contentType = "application/json";
            var utcDate = DateTime.UtcNow;

            var hmacAccessKey = CreateHmac(sharedKey, secretKey, DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                httpMethod, url, contentType, "", "", "", nepOrganization, "");

            var client = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Get, url);
            var gmtDate = utcDate.DayOfWeek.ToString().Substring(0, 3) + ", " +
                          utcDate.ToString("dd MMM yyyy HH:mm:ss") + " GMT";

            request.Headers.Add("nep-organization", nepOrganization);
            request.Headers.Add("date", gmtDate);
            request.Headers.Add("authorization", "AccessKey " + hmacAccessKey);

            var content = new StringContent(String.Empty, Encoding.UTF8, "application/json");
            content.Headers.Remove("Content-Type");
            content.Headers.Add("Content-Type", "application/json");
            request.Content = content;

            var response = await client.SendAsync(request);

            var responseContent = JsonSerializer.Deserialize<ContentModel>(
                await response.Content.ReadAsStringAsync());

            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };


            var formattedJson = JsonSerializer.Serialize(responseContent, options);
            return new ApiResponse
            {
                RoleName = responseContent?.content,
                Token = responseContent?.token,
                StatusCode = (int)response.StatusCode
            };
            //var formattedJson = JsonSerializer.Serialize(responseContent, options);

            //Console.WriteLine("{ \"status\": " + response.StatusCode + " }\n" + formattedJson);
            //return (int)response.StatusCode;
        }


        public class ApiResponse
        {
            public string Token { get; set; }
            public int StatusCode { get; set; }
            public Content[] RoleName { get; set; }
        }
        public static string CreateHmac(
            string sharedKey,
            string secretKey,
            string date,
            string httpMethod,
            string requestUrl,
            string contentType = null,
            string contentMd5 = null,
            string nepApplicationKey = null,
            string nepCorrelationId = null,
            string nepOrganization = null,
            string nepServiceVersion = null)
        {
            var url = new Uri(requestUrl);
            var pathAndQuery = url.PathAndQuery;

            var secretDate = date + ".000Z";
            var oneTimeSecret = secretKey + secretDate;

            var toSign = httpMethod + "\n" + pathAndQuery;

            if (!string.IsNullOrEmpty(contentType))
            {
                toSign += "\n" + contentType;
            }

            if (!string.IsNullOrEmpty(contentMd5))
            {
                toSign += "\n" + contentMd5;
            }

            if (!string.IsNullOrEmpty(nepApplicationKey))
            {
                toSign += "\n" + nepApplicationKey;
            }

            if (!string.IsNullOrEmpty(nepCorrelationId))
            {
                toSign += "\n" + nepCorrelationId;
            }

            if (!string.IsNullOrEmpty(nepOrganization))
            {
                toSign += "\n" + nepOrganization;
            }

            if (!string.IsNullOrEmpty(nepServiceVersion))
            {
                toSign += "\n" + nepServiceVersion;
            }

            var data = Encoding.UTF8.GetBytes(toSign);
            var key = Encoding.UTF8.GetBytes(oneTimeSecret);
            byte[] hash;

            using (var shaM = new HMACSHA512(key))
            {
                hash = shaM.ComputeHash(data);
            }

            var accessKey = sharedKey + ":" + Convert.ToBase64String(hash);
            return accessKey;
        }

        public class InputModel
        {
            public string SecretKey { get; set; }
            public string SharedKey { get; set; }
            public string NepOrganization { get; set; }
        }
        public class Content
        {
            public string roleName { get; set; }
        }

        public class ContentModel
        {
            public string token { get; set; }
            public int maxIdleTime { get; set; }
            public int maxSessionTime { get; set; }
            public int remainingTime { get; set; }
            public string[] authorities { get; set; }
            public string[] consentScopes { get; set; }
            public bool credentialExpired { get; set; }
            public string organizationName { get; set; }
            public string username { get; set; }
            public string[] authenticationMethods { get; set; }
            public int exchangesCompleted { get; set; }
            public string[] customClaims { get; set; }
            public bool singleUse { get; set; }
            public Content[] content { get; set; }
        }
    }
}


