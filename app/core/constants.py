LLM_MODELS = [
    'ibm/granite-3-8b-instruct', # 3.5 star - relevant, fast and easy to understand ***
    'codellama/codellama-34b-instruct-hf', # 0 star - parsing error
    'google/flan-t5-xl', # 0 star
    'google/flan-t5-xxl', # 0 star
    'google/flan-ul2', # 0 star
    'ibm/granite-13b-chat-v2', # deprecated
    'ibm/granite-13b-instruct-v2', # 0 star - takes too much time
    'ibm/granite-20b-code-instruct', # 1 star - not returning json
    'ibm/granite-20b-multilingual', # 2 star - mitigation steps are relevant but generates invalid json
    'ibm/granite-3-2b-instruct', # 1 star - generic
    'ibm/granite-34b-code-instruct', # 0 star 
    'ibm/granite-3b-code-instruct', # 0 star 
    'ibm/granite-7b-lab', # deprecated
    'ibm/granite-8b-code-instruct', # 1 star - generic
    'ibm/granite-8b-japanese-v2-rc',
    'ibm/granite-guardian-3-2b', # 0 star 
    'ibm/granite-guardian-3-8b', # 0 star 
    'meta-llama/llama-2-13b-chat', # 0 star 
    'meta-llama/llama-3-1-70b-instruct', # 3.5 star - relevant ***
    'meta-llama/llama-3-1-8b-instruct', # 2 star - generic answer
    'meta-llama/llama-3-2-11b-vision-instruct',
    'meta-llama/llama-3-2-1b-instruct', # 0 star 
    'meta-llama/llama-3-2-3b-instruct', # 2 star - relevant but prompt needs to be updated
    'meta-llama/llama-3-2-90b-vision-instruct',
    'meta-llama/llama-3-3-70b-instruct', # 3 star - relevant but takes too much time
    'meta-llama/llama-3-405b-instruct', # 0 star - parsing error
    'meta-llama/llama-3-70b-instruct', # 3.5 star - relevant but takes too much time
    'meta-llama/llama-3-8b-instruct', # deprecated
    'meta-llama/llama-guard-3-11b-vision',
    'mistralai/mistral-large', # 2 star - generic answer
    'mistralai/mixtral-8x7b-instruct-v01' # 3 star - relevant answer ***
]

CACHE_NOT_FOUND = "No {name} cache found for {cve}"
UPLOAD_FILE_PATH = "app/data"


SNYK_SAST_RULES = [
    {
        "id": "python/NoHardcodedPasswords",
        "name": "Hardcoded Passwords",
        "shortDescription": "Detection of hardcoded passwords in code that can lead to security vulnerabilities",
        "defaultConfiguration": "warning"
    },
    {
        "id": "python/WebCookieMissesCallToSetSecure",
        "name": "Missing Secure Attribute in Cookies",
        "shortDescription": "Cookies used in HTTPS sessions should include the 'Secure' attribute to prevent interception over unsecured channels",
        "defaultConfiguration": "note"
    },
    {
        "id": "python/Sqli",
        "name": "SQL Injection",
        "shortDescription": "Detection of potential SQL injection vulnerabilities in code",
        "defaultConfiguration": "error",
        "threadClass": "Abuse of Functionality"
    },
    {
        "id": "python/Ssti",
        "name": "Server-Side Template Injection",
        "shortDescription": "Improper handling of user input in templates, leading to potential code execution on the server",
        "defaultConfiguration": "error"
    },
    {
        "id": "python/WebCookieMissesCallToSetHttpOnly",
        "name": "Missing HttpOnly Attribute in Cookies",
        "shortDescription": "Cookies should include the 'HttpOnly' attribute to prevent access via client-side scripts",
        "defaultConfiguration": "note"
    },
    {
        "id": "python/NoHardcodedCredentials",
        "name": "Hardcoded Credentials",
        "shortDescription": "Hardcoded credentials found in code can lead to unauthorized access and security breaches",
        "defaultConfiguration": "note"
    },
    {
        "id": "python/PT",
        "name": "Path Traversal",
        "shortDescription": "Detection of path traversal vulnerabilities that may allow attackers to access restricted files",
        "defaultConfiguration": "error",
        "threadClass": "Path Traversal"
    },
    {
        "id": "python/CodeInjection",
        "name": "Code Injection",
        "shortDescription": "Detection of potential code injection vulnerabilities that may allow execution of malicious code",
        "defaultConfiguration": "error"
    },
    {
        "id": "python/XSS",
        "name": "Cross-Site Scripting (XSS)",
        "shortDescription": "Detection of cross-site scripting vulnerabilities that allow attackers to inject malicious scripts",
        "defaultConfiguration": "error",
        "threadClass": "Cross-site Scripting"
    },
    {
        "id": "python/InsecureHash",
        "name": "Insecure Hash Algorithm",
        "shortDescription": "Detection of weak or insecure hash algorithms used for password storage or other sensitive data",
        "defaultConfiguration": "note"
    },
    {
        "id": "python/ServerInformationExposure",
        "name": "Server Information Exposure",
        "shortDescription": "Detection of server information being exposed, which can aid attackers in reconnaissance",
        "defaultConfiguration": "warning"
    },
    {
        "id": "python/CommandInjection",
        "name": "Command Injection",
        "shortDescription": "Command Injection",
        "defaultConfiguration": "error",
        "threadClass": "Abuse of Functionality"
    },
    {
        "id": "python/RunWithDebugTrue",
        "name": "Run With Debug True",
        "shortDescription": "Debug Mode Enabled",
        "defaultConfiguration": "warning",
        "threadClass": "Abuse of Functionality"
    }
]
