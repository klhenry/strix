"""Quick test script for the reporting module."""

from pathlib import Path

from strix.reporting.models import ScanReport, ScanMetadata, VulnerabilityReport, CvssBreakdown, CodeLocation
from strix.reporting.html_report import generate_html_report
from strix.reporting.json_report import generate_json_summary
from strix.reporting.sarif_report import generate_sarif_report

report = ScanReport(
    metadata=ScanMetadata(
        run_id="test-run-001",
        run_name="test-run",
        start_time="2026-03-23T10:00:00+00:00",
        end_time="2026-03-23T10:30:00+00:00",
        targets=["https://example.com"],
        status="completed",
    ),
    vulnerabilities=[
        VulnerabilityReport(
            id="vuln-0001",
            title="SQL Injection in Login Endpoint",
            severity="critical",
            timestamp="2026-03-23 10:15:00 UTC",
            description="User input is passed directly to a SQL query without sanitization.",
            impact="An attacker can extract the entire database, modify data, or escalate privileges.",
            target="https://example.com",
            technical_analysis="The /api/login endpoint concatenates the username parameter directly into a SQL query string.",
            poc_description="Send a single quote in the username field to trigger a SQL error.",
            poc_script_code='curl -X POST https://example.com/api/login -d "user=admin\'--&pass=x"',
            remediation_steps="Use parameterized queries instead of string concatenation.",
            cvss=9.8,
            cvss_breakdown=CvssBreakdown(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H",
            ),
            endpoint="/api/login",
            method="POST",
            cwe="CWE-89",
            code_locations=[
                CodeLocation(
                    file="src/db/queries.ts",
                    start_line=42,
                    end_line=45,
                    snippet='const query = `SELECT * FROM users WHERE name = ${name}`;',
                    label="Unsanitized input used in SQL query",
                    fix_before='const query = `SELECT * FROM users WHERE name = ${name}`;',
                    fix_after="const query = 'SELECT * FROM users WHERE name = $1';\nconst result = await db.query(query, [name]);",
                ),
            ],
        ),
        VulnerabilityReport(
            id="vuln-0002",
            title="Cross-Site Scripting (XSS) in Search",
            severity="high",
            timestamp="2026-03-23 10:20:00 UTC",
            description="Reflected XSS in the search parameter allows script injection.",
            impact="Session hijacking, credential theft, defacement.",
            target="https://example.com",
            technical_analysis="The search query parameter is reflected in the response without encoding.",
            poc_description="Inject a script tag via the search parameter.",
            poc_script_code='curl "https://example.com/search?q=<script>alert(1)</script>"',
            remediation_steps="HTML-encode all user input before rendering in the page.",
            cvss=7.1,
            cvss_breakdown=CvssBreakdown(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="C", confidentiality="L", integrity="L", availability="N",
            ),
            endpoint="/search",
            method="GET",
            cwe="CWE-79",
        ),
        VulnerabilityReport(
            id="vuln-0003",
            title="Missing Rate Limiting on Password Reset",
            severity="medium",
            timestamp="2026-03-23 10:25:00 UTC",
            description="The password reset endpoint has no rate limiting.",
            impact="Brute-force attacks on reset tokens or email flooding.",
            target="https://example.com",
            technical_analysis="No rate limit headers observed; 1000 requests in 10 seconds all returned 200.",
            poc_description="Send rapid password reset requests.",
            poc_script_code="for i in range(1000):\n    requests.post('https://example.com/api/reset', json={'email': 'victim@test.com'})",
            remediation_steps="Add rate limiting (e.g., 5 requests per minute per IP).",
            cvss=5.3,
            endpoint="/api/reset",
            method="POST",
        ),
    ],
    executive_summary="Testing identified 3 vulnerabilities: 1 critical SQL injection, 1 high XSS, and 1 medium missing rate limit.",
    methodology="Testing followed OWASP WSTG methodology with automated and manual techniques.",
    technical_analysis="The application has significant input validation gaps across multiple endpoints.",
    recommendations="1. Immediately fix the SQL injection.\n2. Implement output encoding for XSS.\n3. Add rate limiting to sensitive endpoints.",
)

out = Path("test_output")
out.mkdir(exist_ok=True)

html_path = generate_html_report(report, out / "report.html", client_name="Acme Health Services")
json_path = generate_json_summary(report, out / "report.json")
sarif_path = generate_sarif_report(report, out / "results.sarif")

print(f"HTML:  {html_path}")
print(f"JSON:  {json_path}")
print(f"SARIF: {sarif_path}")
print()
print("Open the HTML report with:")
print(f"  open {html_path}")
