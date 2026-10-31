// Swagger UI, configured from an external file because the CSP forbids inline scripts.
window.ui = SwaggerUIBundle({
  url: "/api/openapi.json", dom_id: "#swagger", deepLinking: true, persistAuthorization: true,
  docExpansion: "list", defaultModelsExpandDepth: 0, tryItOutEnabled: true, displayRequestDuration: true,
});
