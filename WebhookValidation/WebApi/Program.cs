using WebhookValidation;

var builder = WebApplication.CreateBuilder(args);

var options = new WebhookValidationOptions();
builder.Configuration.GetSection("WebhookValidation").Bind(options);

var validator = WebhookValidator.FromPublicKeyDerBase64(options.PublicKeyDerBase64!);

builder.Services.AddSingleton(validator);
builder.Services.AddScoped<WebhookSignatureValidationFilter>();

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseRouting();
app.MapControllers();

app.Run();

internal class WebhookValidationOptions
{
    public string? PublicKeyDerBase64 { get; set; }
}