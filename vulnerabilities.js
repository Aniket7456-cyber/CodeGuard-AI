/**
 * CODEGUARD AI — Vulnerability Intelligence Database
 * Maps detected patterns to CWE, explanations, attack vectors, and remediation.
 */

const VULNERABILITY_DATABASE = {
    sqli: {
        id: 'sqli',
        title: 'SQL Injection',
        severity: 'critical',
        cwe: 'CWE-89',
        confidence: '98%',
        affectedLine: 'Line 5-7',
        risk: 'User-controlled input is directly concatenated into an SQL query string without parameterization.',
        whatHappened: 'The application constructs a database query by binding raw string variables received directly from user input.',
        whyDangerous: 'An attacker can supply malicious SQL payloads (e.g., `\' OR \'1\'=\'1`) to bypass authentication, dump database contents, or execute administrative drop/delete statements.',
        attackChain: ['USER INPUT', 'UNSAFE QUERY', 'SQL INJECTION', 'DATABASE COMPROMISE'],
        recommendation: 'Use parameterized queries (prepared statements) or an ORM that separates SQL command syntax from user data parameters.',
        vulnerableSnippet: `import sqlite3

username = input("Enter username: ")
connection = sqlite3.connect("users.db")
query = "SELECT * FROM users WHERE username='" + username + "'"
result = connection.execute(query)
print(result.fetchall())`,
        secureSnippet: `import sqlite3

username = input("Enter username: ")
connection = sqlite3.connect("users.db")
# Parameterized query protects against injection
query = "SELECT * FROM users WHERE username = ?"
cursor = connection.cursor()
cursor.execute(query, (username,))
print(cursor.fetchall())`
    },
    xss: {
        id: 'xss',
        title: 'Cross-Site Scripting (XSS)',
        severity: 'high',
        cwe: 'CWE-79',
        confidence: '95%',
        affectedLine: 'Line 3',
        risk: 'Unsanitized user input is rendered directly into the Document Object Model (DOM) or HTML response.',
        whatHappened: 'Untrusted data received from query parameters or forms is injected into webpage markup without proper entity encoding.',
        whyDangerous: 'Attackers can execute arbitrary JavaScript in victim browsers to steal session cookies, hijack accounts, or deface the application interface.',
        attackChain: ['MALICIOUS PAYLOAD', 'UNFILTERED DOM', 'SCRIPT EXECUTION', 'SESSION HIJACK'],
        recommendation: 'Sanitize and encode all user-supplied output before rendering. Use modern frameworks with automatic template escaping.',
        vulnerableSnippet: `// Unsafe DOM rendering
const comment = req.query.comment;
document.getElementById('user-comments').innerHTML = "<div class='comment'>" + comment + "</div>";`,
        secureSnippet: `// Secure textContent rendering
const comment = req.query.comment;
const div = document.createElement('div');
div.className = 'comment';
div.textContent = comment; // Safely encodes HTML entities
document.getElementById('user-comments').appendChild(div);`
    },
    secret: {
        id: 'secret',
        title: 'Hardcoded Secret / API Key',
        severity: 'critical',
        cwe: 'CWE-798',
        confidence: '99%',
        affectedLine: 'Line 2',
        risk: 'Plaintext cryptographic keys, passwords, or cloud API tokens are embedded directly into source code.',
        whatHappened: 'Sensitive authentication credentials were committed directly into the source code repository instead of externalized environment variables.',
        whyDangerous: 'Anyone with read access to the repository (or decompiled binary) gains instant unauthorized access to connected cloud infrastructure, databases, or payment gateways.',
        attackChain: ['CODE REPOSITORY', 'CREDENTIAL EXPOSURE', 'UNAUTHORIZED ACCESS', 'INFRASTRUCTURE BREACH'],
        recommendation: 'Move all secrets to environment variables (`process.env.API_KEY`, `os.environ`) and use secret manager services.',
        vulnerableSnippet: `// Hardcoded production API secret
const stripe = require('stripe')('sk_live_51Nc928374910283749102837');
const apiKey = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";`,
        secureSnippet: `// Load secrets securely from environment configuration
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const apiKey = process.env.GITHUB_API_KEY;`
    },
    cmdi: {
        id: 'cmdi',
        title: 'Command Injection',
        severity: 'critical',
        cwe: 'CWE-78',
        confidence: '96%',
        affectedLine: 'Line 4',
        risk: 'User-controlled input is passed directly to system shell execution functions.',
        whatHappened: 'The application executes operating system commands using unvalidated parameter strings.',
        whyDangerous: 'An attacker can append shell metacharacters (`;&|`) to execute arbitrary system commands with application privileges, leading to complete server takeover.',
        attackChain: ['USER INPUT', 'SHELL CONCAT', 'ARBITRARY EXECUTION', 'SERVER TAKEOVER'],
        recommendation: 'Avoid shell execution functions (`os.system`, `exec`). Use safe API alternatives with argument arrays (`subprocess.run(['ping', host])`).',
        vulnerableSnippet: `import os
target = input("Enter host to ping: ")
# Vulnerable shell injection point
os.system("ping -c 1 " + target)`,
        secureSnippet: `import subprocess
target = input("Enter host to ping: ")
# Safe execution without shell interpretation
subprocess.run(["ping", "-c", "1", target], check=True)`
    },
    eval: {
        id: 'eval',
        title: 'Dangerous eval() Usage',
        severity: 'high',
        cwe: 'CWE-95',
        confidence: '92%',
        affectedLine: 'Line 2',
        risk: 'Dynamic code evaluation function receives untrusted string input.',
        whatHappened: 'The application evaluates arbitrary code strings at runtime using `eval()` or `Function()` constructors.',
        whyDangerous: 'Allows attackers to execute arbitrary code within the security context of the application runtime.',
        attackChain: ['UNTRUSTED INPUT', 'EVAL() EXECUTION', 'ARBITRARY CODE RUN', 'SYSTEM COMPROMISE'],
        recommendation: 'Never use `eval()`. Use safe parsing libraries like `JSON.parse()` for data structures.',
        vulnerableSnippet: `// Dangerous runtime evaluation
const userInput = req.body.formula;
const result = eval(userInput);`,
        secureSnippet: `// Safe parsing or arithmetic validation
const userInput = req.body.formula;
// Use a secure math parser library instead of eval
const result = safeMathParser(userInput);`
    },
    path: {
        id: 'path',
        title: 'Path Traversal',
        severity: 'medium',
        cwe: 'CWE-22',
        confidence: '90%',
        affectedLine: 'Line 6',
        risk: 'File system operations use unvalidated relative path inputs containing directory traversal sequences.',
        whatHappened: 'User input containing `../` sequences is concatenated directly into file paths.',
        whyDangerous: 'Enables attackers to read or write sensitive system files outside the intended web root directory (`/etc/passwd`, config files).',
        attackChain: ['TRAVERSAL PAYLOAD', 'PATH CONCAT', 'UNAUTHORIZED FILE READ', 'DATA LEAK'],
        recommendation: 'Use `path.resolve()` and verify that the resulting file path starts with the intended base directory.',
        vulnerableSnippet: `const fs = require('fs');
const filename = req.query.file;
// Vulnerable path traversal
const content = fs.readFileSync('./uploads/' + filename, 'utf8');`,
        secureSnippet: `const path = require('path');
const fs = require('fs');
const safeBaseDir = path.resolve('./uploads');
const requestedPath = path.resolve(safeBaseDir, req.query.file);

if (!requestedPath.startsWith(safeBaseDir)) {
    throw new Error('Access denied: Path traversal detected.');
}
const content = fs.readFileSync(requestedPath, 'utf8');`
    }
};
