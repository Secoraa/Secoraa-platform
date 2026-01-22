import os
import base64
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles


# ==========================================
# Paths
# ==========================================
BASE_DIR = os.path.dirname(__file__)                # /apis
SWAGGER_DIR = os.path.join(BASE_DIR, "swagger")     # /apis/swagger


# ==========================================
# Static Files (Logo)
# ==========================================
def mount_static_files(app: FastAPI):
    """Mount static swagger directory and serve favicon."""
    app.mount("/static", StaticFiles(directory=SWAGGER_DIR), name="static")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        logo_path = os.path.join(SWAGGER_DIR, "secoraa.jpg")
        if not os.path.exists(logo_path):
            return FileResponse(status_code=404)
        return FileResponse(logo_path, media_type="image/jpeg")


# ==========================================
# Helper → Load logo as Base64
# ==========================================
def load_logo_base64():
    logo_path = os.path.join(SWAGGER_DIR, "secoraa.jpg")
    if not os.path.exists(logo_path):
        return ""

    with open(logo_path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode()
        return f"data:image/jpeg;base64,{encoded}"


# ==========================================
# Custom Swagger & Redoc Docs
# ==========================================
def register_custom_docs(app: FastAPI, docs_path: str):
    logo_data_uri = load_logo_base64()

    # ------------------------------
    # Custom Swagger UI
    # ------------------------------
    @app.get(docs_path, include_in_schema=False)
    async def custom_swagger_ui():
        # Use static URL for favicon
        favicon_url = "/static/secoraa.jpg"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secoraa-Backend Service - API Docs</title>
            <link rel="icon" type="image/jpeg" href="{favicon_url}">
            <link rel="shortcut icon" type="image/jpeg" href="{favicon_url}">

            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />

            <style>
                .topbar {{
                    background-color: #1f2937 !important;
                }}
                /* Hide default FastAPI logo and text */
                .topbar-wrapper .link {{
                    display: none !important;
                }}
                .topbar-wrapper img {{
                    display: none !important;
                }}
                .topbar-wrapper svg {{
                    display: none !important;
                }}
                .topbar-wrapper span {{
                    display: none !important;
                }}
                /* Add custom logo */
                .topbar-wrapper {{
                    display: flex !important;
                    align-items: center !important;
                    padding: 10px 20px !important;
                }}
                .topbar-wrapper::before {{
                    content: "";
                    display: inline-block;
                    width: 40px;
                    height: 40px;
                    background-image: url("{logo_data_uri}");
                    background-size: contain;
                    background-repeat: no-repeat;
                    background-position: center;
                    margin-right: 10px;
                    flex-shrink: 0;
                }}
                .topbar-wrapper::after {{
                    content: "Secoraa Backend Service";
                    font-size: 20px;
                    color: white;
                    font-weight: bold;
                    display: inline-block;
                }}
            </style>
        </head>

        <body>
            <div id="swagger-ui"></div>

            <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
            <script>
                window.onload = function() {{
                    SwaggerUIBundle({{
                        url: "{app.openapi_url}",
                        dom_id: '#swagger-ui',
                        deepLinking: true,
                        layout: "BaseLayout",
                        presets: [
                            SwaggerUIBundle.presets.apis,
                            SwaggerUIBundle.presets.standalone
                        ]
                    }});
                    
                    // Additional customization after Swagger UI loads
                    function replaceFastAPILogo() {{
                        // Hide any remaining FastAPI logos and elements
                        const selectors = [
                            '.topbar-wrapper .link',
                            '.topbar-wrapper img',
                            '.topbar-wrapper svg',
                            '.topbar-wrapper span',
                            '.topbar-wrapper a[href*="fastapi"]'
                        ];
                        
                        selectors.forEach(selector => {{
                            const elements = document.querySelectorAll(selector);
                            elements.forEach(el => {{
                                el.style.display = 'none';
                                el.style.visibility = 'hidden';
                            }});
                        }});
                    }}
                    
                    // Run immediately and after delays to catch dynamically loaded content
                    replaceFastAPILogo();
                    setTimeout(replaceFastAPILogo, 100);
                    setTimeout(replaceFastAPILogo, 500);
                    setTimeout(replaceFastAPILogo, 1000);
                    
                    // Also use MutationObserver to catch any late-loading elements
                    const observer = new MutationObserver(replaceFastAPILogo);
                    observer.observe(document.body, {{
                        childList: true,
                        subtree: true
                    }});
                }};
            </script>
        </body>
        </html>
        """
        return HTMLResponse(html)

    # ------------------------------
    # Custom ReDoc UI
    # ------------------------------
    @app.get("/api/v1alpha1/admin/redoc", include_in_schema=False)
    async def custom_redoc():
        favicon_url = "/static/secoraa.jpg"
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secoraa Backend Service - ReDoc</title>
            <link rel="icon" type="image/jpeg" href="{favicon_url}">
            <link rel="shortcut icon" type="image/jpeg" href="{favicon_url}">

            <style>
                body {{
                    margin: 0;
                    padding: 0;
                }}
            </style>
        </head>

        <body>
            <redoc spec-url="{app.openapi_url}"></redoc>
            <script src="https://cdn.jsdelivr.net/npm/redoc/bundles/redoc.standalone.js"></script>
        </body>
        </html>
        """
        return HTMLResponse(html)
