# Content Length Fixer

This is a Burp extension that detects requests with an incorrect Content-Length header.
When an incorrect header is detected an alert is issued, and an information scan issue is created that contains the request.
If Burp tools are generating incorrect lengths, please notify PortSwigger.