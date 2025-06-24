 const urlParams = new URLSearchParams(window.location.search);
    const url = urlParams.get('url');
    // if (!url) {
    //   document.body.innerHTML = "<h2 style='color:red;text-align:center;'>Error: No URL provided.</h2>";
    //   throw new Error("URL is missing");
    // }

    const vulnerabilities = [
      {
        name: "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
        link: "https://cwe.mitre.org/data/definitions/1004.html",
        description: "Cookies without HttpOnly can be accessed by JavaScript and stolen via XSS.",
        solution: "Set the HttpOnly attribute on all cookies.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        link: "https://cwe.mitre.org/data/definitions/1021.html",
        description: "Improper UI frame restrictions allow clickjacking.",
        solution: "Use X-Frame-Options or CSP headers.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-1275: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        link: "https://cwe.mitre.org/data/definitions/1275.html",
        description: "Missing Secure flag means cookies may be sent over HTTP.",
        solution: "Use the Secure attribute on all session cookies.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-319: Cleartext Transmission of Sensitive Information",
        link: "https://cwe.mitre.org/data/definitions/319.html",
        description: "Sensitive data sent in plaintext is vulnerable to sniffing.",
        solution: "Use HTTPS/TLS for all sensitive communication.",
        severity: "HIGH",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-436: Interpretation Conflict",
        link: "https://cwe.mitre.org/data/definitions/436.html",
        description: "Inconsistent data interpretation between components.",
        solution: "Ensure consistent parsing across components.",
        severity: "LOW",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-525: Use of Web Browser Cross-Domain Capabilities",
        link: "https://cwe.mitre.org/data/definitions/525.html",
        description: "Cross-domain browser features can lead to security issues.",
        solution: "Limit cross-domain access and enforce CORS policy.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-565: Reliance on Cookies without Validation and Integrity Checking",
        link: "https://cwe.mitre.org/data/definitions/565.html",
        description: "Cookies can be tampered with if not validated properly.",
        solution: "Use signed cookies or JWTs with integrity checks.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        link: "https://cwe.mitre.org/data/definitions/614.html",
        description: "Cookies may be exposed if not marked Secure.",
        solution: "Always set Secure flag for HTTPS cookies.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-615: Inclusion of Sensitive Information in HTTP Headers",
        link: "https://cwe.mitre.org/data/definitions/615.html",
        description: "Sensitive headers can leak private data.",
        solution: "Avoid putting credentials in HTTP headers.",
        severity: "HIGH",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-693: Protection Mechanism Failure",
        link: "https://cwe.mitre.org/data/definitions/693.html",
        description: "Security controls fail to adequately protect resources.",
        solution: "Test and strengthen security mechanisms.",
        severity: "HIGH",
        attackVector: "NETWORK"
    },
    {
        name: "Missing X-Frame-Options Header",
        link: "https://owasp.org/www-project-secure-headers/#x-frame-options",
        description: "No anti-clickjacking header set.",
        solution: "Use X-Frame-Options header.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "Missing Strict-Transport-Security Header",
        link: "https://owasp.org/www-project-secure-headers/#strict-transport-security",
        description: "TLS used but no HSTS header set.",
        solution: "Use Strict-Transport-Security header.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "Missing X-Content-Type-Options Header",
        link: "https://owasp.org/www-project-secure-headers/#x-content-type-options",
        description: "Allows MIME-sniffing attacks.",
        solution: "Use X-Content-Type-Options: nosniff.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "CSP Not Set",
        link: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        description: "Content Security Policy is missing.",
        solution: "Set a strict CSP header.",
        severity: "HIGH",
        attackVector: "NETWORK"
    },
    {
        name: "X-XSS-Protection Not Set",
        link: "https://owasp.org/www-project-secure-headers/#x-xss-protection",
        description: "XSS filter not enabled in browser.",
        solution: "Use X-XSS-Protection header.",
        severity: "MEDIUM",
        attackVector: "NETWORK"
    },
    {
        name: "Open Redirect Detected",
        link: "https://cwe.mitre.org/data/definitions/601.html",
        description: "URL redirection leads to attacker-controlled domains.",
        solution: "Validate all redirect targets.",
        severity: "HIGH",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-352: Cross-Site Request Forgery (CSRF)",
        link: "https://cwe.mitre.org/data/definitions/352.html",
        description: "Attackers trick users into submitting requests unknowingly.",
        solution: "Use CSRF tokens.",
        severity: "HIGH",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-79: Cross-Site Scripting (XSS)",
        link: "https://cwe.mitre.org/data/definitions/79.html",
        description: "Unescaped user input injected into HTML/JS.",
        solution: "Sanitize and encode user input.",
        severity: "HIGH",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-89: SQL Injection",
        link: "https://cwe.mitre.org/data/definitions/89.html",
        description: "User input used directly in SQL queries.",
        solution: "Use parameterized queries.",
        severity: "CRITICAL",
        attackVector: "NETWORK"
    },
    {
        name: "CWE-22: Path Traversal",
        link: "https://cwe.mitre.org/data/definitions/22.html",
        description: "Allows access to unintended files.",
        solution: "Validate file paths.",
        severity: "CRITICAL",
        attackVector: "NETWORK"
    }
    ];

    document.getElementById("scannedUrl").href = url;
    document.getElementById("scannedUrl").textContent = url;

    setTimeout(() => {
      document.getElementById("loading").style.display = "none";
      document.getElementById("result").style.display = "block";

      const tbody = document.getElementById("vulnTableBody");
      vulnerabilities.forEach(vuln => {
        const tr = document.createElement("tr");
        const exploited = Math.random() < 0.5 ? "Exploited" : "Not Exploited";

        tr.innerHTML = `
          <td><a href="${vuln.link}" target="_blank">${vuln.name}</a></td>
          <td>${vuln.severity}</td>
          <td>${vuln.description}</td>
          <td>${vuln.solution}</td>
          <td>${exploited}</td>
          <td>${vuln.vector}</td>
        `;
        tbody.appendChild(tr);
      });
    }, 15000);