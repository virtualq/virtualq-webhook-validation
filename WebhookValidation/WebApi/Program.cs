using WebhookValidation;

var builder = WebApplication.CreateBuilder(args);

var options = new WebhookValidationOptions();
builder.Configuration.GetSection("WebhookValidation").Bind(options);

var validator = WebhookValidator.FromPublicKeyDerBase64(options.PublicKeyDerBase64!);

builder.Services.AddSingleton(validator);
builder.Services.AddScoped<WebhookSignatureValidationFilter>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();


app.MapPost("/api/v1/webhook", (HttpContext context) => "").AddEndpointFilter(validator.Filter);

app.Run();

internal class WebhookValidationOptions
{
    public string? PublicKeyDerBase64 { get; set; }
}