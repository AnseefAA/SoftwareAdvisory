from rapidfuzz import process

# Define security techniques
VULNERABILITY_CLASS_TECHNIQUE = {
    "SQL Injection": "Use parameterized queries",
    "Command Injection": "Sanitize inputs and request data, For Python: Use `shlex` to safely parse commands",
    "Cross-Site Scripting (XSS)": "Sanitize html string. In Python: use `html.escape` to sanitize",
    "Cross-Site Request Forgery (CSRF)": "Use anti-CSRF tokens",
    "Clickjacking": "Implement the X-Frame-Options header",
    "Insecure Direct Object References": "Implement access control checks",
    "Security Misconfiguration": "Regularly update and patch systems",
    "Sensitive Data Exposure": "Use encryption (at rest and in transit)",
    "Broken Authentication": "Implement multi-factor authentication",
    "Insufficient Logging and Monitoring": "Ensure comprehensive logging and real-time monitoring",
    "Insufficient Process Validation": "Implement inputs validation, data type checks, and ensure only valid data is processed at all stages",
    "Path Traversal": "Use os.path.abspath() to resolve the full path and verify it's within the allowed directory, ensure user-supplied file paths do not contain .. (dot-dot) sequences",
    "Hardcoded Credentials": "Use environment variable"
}


PROGRAMMING_LANGUAGE_COMMENTS = {
    "Python": "hash (#)",
    "py": "hash (#)",
    "YAML": "hash (#)",
    "Dockerfile": "hash (#)",
    "JavaScript": "Double slash (//)",
    "Java": "Double slash (//)",
    "C": "Double slash (//)",
    "C++": "Double slash (//)",
    "Go": "Double slash (//)",
    "Swift": "Double slash (//)",
    "TypeScript": "Double slash (//)",
    "SQL": "Double dash (--)",
    "HTML": "<!-- -->",
    "XML": "<!-- -->"
}

def fetch_mitigation_technique(user_query):
    """
    Finds the closest security technique using fuzzy matching.

    Args:
        user_query (str): The user's query string.

    Returns:
        tuple: (best matching technique, security guidance)
    """
    best_match, score, _ = process.extractOne(user_query, VULNERABILITY_CLASS_TECHNIQUE.keys())

    # Set a threshold for a valid match
    if score > 80:  # 60% similarity threshold
        return VULNERABILITY_CLASS_TECHNIQUE[best_match]
    else:
        return None
    

def fetch_comment_style(language_query):
    """
    Finds the closest matching programming language and returns its comment style.

    Args:
        language_query (str): The user's input for a programming language.

    Returns:
        str: The corresponding comment symbol or None if no suitable match is found.
    """
    best_match, score, _ = process.extractOne(language_query, PROGRAMMING_LANGUAGE_COMMENTS.keys())

    # Set a threshold for a valid match
    if score > 80:  # 60% similarity threshold
        return PROGRAMMING_LANGUAGE_COMMENTS[best_match]
    else:
        return None
    

