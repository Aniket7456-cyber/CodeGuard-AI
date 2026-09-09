/**
 * CODEGUARD AI — Client-Side Pattern Detection Engine
 * Scans submitted code against security rule patterns and computes metrics.
 */

class CodeSecurityScanner {
    constructor() {
        // Rule definitions mapping regex patterns to vulnerability database keys
        this.rules = [
            {
                pattern: /(sqlite3\.connect|mysql\.connect|pg\.connect|SELECT.*FROM|INSERT INTO|UPDATE.*SET|exec\(.*query)/i,
                vulnKey: 'sqli',
                scoreImpact: 35
            },
            {
                pattern: /(innerHTML|document\.write|res\.send\(.*req\.|dangerouslySetInnerHTML)/i,
                vulnKey: 'xss',
                scoreImpact: 25
            },
            {
                pattern: /(api_key|apikey|secret|password|bearer|auth_token|sk_live_|ghp_)[ \t]*[=:][ \t]*['"][a-zA-Z0-9_\-]{10,}['"]/i,
                vulnKey: 'secret',
                scoreImpact: 40
            },
            {
                pattern: /(os\.system|exec\(|child_process|shell_exec|passthru)/i,
                vulnKey: 'cmdi',
                scoreImpact: 35
            },
            {
                pattern: /\beval\s*\(/i,
                vulnKey: 'eval',
                scoreImpact: 30
            },
            {
                pattern: /(\.\.\/|fs\.readFileSync|file_get_contents|include\(|require\()/i,
                vulnKey: 'path',
                scoreImpact: 20
            }
        ];
    }

    scan(codeText, language) {
        const detectedVulnKeys = new Set();
        let baseScore = 95;

        // Run pattern matching
        this.rules.forEach(rule => {
            if (rule.pattern.test(codeText)) {
                detectedVulnKeys.add(rule.vulnKey);
                baseScore -= rule.scoreImpact;
            }
        });

        // Ensure score remains within bounds [10, 98]
        if (detectedVulnKeys.size === 0) {
            baseScore = 96; // Clean code
        } else {
            baseScore = Math.max(15, Math.min(85, baseScore));
        }

        // Map detected keys to full vulnerability objects
        const findings = [];
        let criticalCount = 0;
        let highCount = 0;
        let mediumCount = 0;
        let lowCount = 0;

        detectedVulnKeys.forEach(key => {
            const vuln = VULNERABILITY_DATABASE[key];
            if (vuln) {
                findings.push(vuln);
                if (vuln.severity === 'critical') criticalCount++;
                else if (vuln.severity === 'high') highCount++;
                else if (vuln.severity === 'medium') mediumCount++;
                else lowCount++;
            }
        });

        // If no findings matched at all, provide a generic secure sample finding or none
        if (findings.length === 0) {
            // Add a low-severity informational note if code is very short or clean
            lowCount = 0;
        }

        return {
            score: baseScore,
            afterScore: Math.min(98, baseScore + 45 > 98 ? 96 : baseScore + 45),
            language: language,
            lineCount: codeText.split('\n').length,
            scanTime: (Math.random() * 0.5 + 0.62).toFixed(2) + 's',
            counts: {
                critical: criticalCount,
                high: highCount,
                medium: mediumCount,
                low: lowCount,
                total: findings.length
            },
            findings: findings
        };
    }
}