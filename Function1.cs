using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

public class SnowflakeHandler
{
    [Function("SnowflakeHandler")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
        FunctionContext executionContext)
    {
        var logger = executionContext.GetLogger("SnowflakeHandler");
        logger.LogInformation("Request received.");

        var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        var data = JsonSerializer.Deserialize<JsonElement>(requestBody);

        var inputParam = data.GetProperty("input_param").GetString() ?? "No input provided";

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        await response.WriteAsJsonAsync(new { message = $"Received input: {inputParam}", status = "success" });

        return response;
    }
}
