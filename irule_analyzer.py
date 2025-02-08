import re

def analyze_irule(irule_content):
    """
    Enhanced iRule analyzer with XC migration recommendations and original functionality
    """
    analysis = {
        "mappable": [],        # Can be directly mapped to XC features
        "alternatives": [],     # Requires alternative implementation
        "unsupported": [],     # Currently not possible in XC
        "warnings": [],        # Additional considerations
        "recommendations": []   # Specific XC feature recommendations
    }
    
    print(f"Starting iRule content analysis...")
    print(f"Content snippet: {irule_content[:100]}")
    
    # Check for common patterns first
    check_common_patterns(irule_content, analysis)
    
    # Event-specific analysis
    events = {
        'RULE_INIT': check_rule_init_capabilities,
        'CLIENT_ACCEPTED': check_client_accepted_capabilities,
        'CLIENTSSL_HANDSHAKE': check_clientssl_handshake_capabilities,
        'CLIENTSSL_CLIENTCERT': check_clientssl_clientcert_capabilities,
        'HTTP_REQUEST': check_http_request_capabilities,
        'HTTP_REQUEST_DATA': check_http_request_data_capabilities,
        'HTTP_RESPONSE': check_http_response_capabilities,
        'HTTP_RESPONSE_DATA': check_http_response_data_capabilities,
        'LB_SELECTED': check_lb_selected_capabilities,
        'LB_FAILED': check_lb_failed_capabilities
    }
    
    # Extract and analyze each event
    for event, checker in events.items():
        print(f"Checking for {event} event...")
        if re.search(rf'when\s+{event}\s*{{', irule_content, re.IGNORECASE):
            print(f"Found {event} event")
            event_content = extract_event_content(irule_content, event)
            if event_content:
                print(f"Analyzing {event} content...")
                checker(event_content, analysis)
                print(f"Completed {event} analysis")
            else:
                print(f"No content found for {event}")
    
    return analysis

def check_common_patterns(content, analysis):
    """Check for common iRule patterns that have direct XC equivalents"""
    
    # Original pattern checks
    if re.search(r'HTTP::header', content):
        analysis["mappable"].append({
            "feature": "Header Manipulation",
            "service_policy": "Request/Response Headers Action in service policy",
            "notes": "Header modifications available at both LB and route level"
        })
    
    if re.search(r'IP::client_addr|IP::local_addr', content):
        analysis["mappable"].append({
            "feature": "IP address matching",
            "service_policy": "IP Prefix List Matcher in service policy",
            "notes": "Client IP matching supported in service policies"
        })

    # New pattern checks from documentation
    if re.search(r'HTTP::redirect', content):
        analysis["mappable"].append({
            "feature": "HTTP Redirects",
            "service_policy": "HTTP Load Balancer checkbox or L7 route configuration",
            "notes": "Simple redirects are a checkbox, complex redirects use L7 routes"
        })

    # Check for logging patterns
    if re.search(r'log\s+local', content):
        analysis["alternatives"].append({
            "feature": "Custom Logging",
            "alternative": "XC built-in telemetry and logging",
            "notes": "XC provides comprehensive logging with headers, SSL info, etc."
        })

    # Check for websocket handling
    if 'HTTP::is_websocket' in content or 'WebSocket' in content:
        analysis["mappable"].append({
            "feature": "WebSocket Support",
            "service_policy": "WebSocket configuration in Load Balancer",
            "notes": "Native WebSocket support with proper configuration"
        })

    # TCP option and proxy protocol
    if re.search(r'TCP::option', content):
        analysis["alternatives"].append({
            "feature": "TCP Options",
            "alternative": "Proxy Protocol in Origin Pool Settings",
            "notes": "Use Proxy Protocol instead of TCP Option 28 for client IP"
        })

    # Error page handling
    if re.search(r'HTTP::respond|HTTP::status', content):
        analysis["mappable"].append({
            "feature": "Custom Error Pages",
            "service_policy": "Custom Error Response in Load Balancer",
            "notes": "Supports custom error pages with dynamic content"
        })

    # Keep-alive and connection header handling
    if re.search(r'Connection|Keep-Alive', content):
        analysis["warnings"].append({
            "feature": "HTTP Connection Headers",
            "note": "Connection headers prohibited in HTTP/2 and HTTP/3",
            "recommendation": "Configure timeouts in LB and Origin settings"
        })

    # Complex string manipulation
    if re.search(r'(regexp|regsub|substr|replace)', content):
        analysis["warnings"].append({
            "feature": "Complex string manipulation",
            "note": "Consider service policies or NGINX service chaining"
        })

    # Health monitoring
    if re.search(r'monitor\s+|health_check', content):
        analysis["mappable"].append({
            "feature": "Health Monitoring",
            "service_policy": "Health Checks in Origin Pool",
            "notes": "Configure proper timeouts and HTTP version"
        })

def check_rule_init_capabilities(content, analysis):
    """Enhanced RULE_INIT analysis"""
    # Original functionality
    if re.search(r'set\s+static::', content):
        analysis["alternatives"].append({
            "feature": "Static variable initialization",
            "alternative": "System metadata or LB configuration"
        })
    
    # New functionality
    if re.search(r'table\s+set', content):
        analysis["unsupported"].append({
            "feature": "iRule tables",
            "note": "Consider XC metadata or custom configuration"
        })

    # Data group handling
    if re.search(r'class\s+match|data\s+group', content):
        analysis["alternatives"].append({
            "feature": "Data Groups",
            "alternative": "Service Policies or Custom Metadata",
            "notes": "Use service policies for matching conditions"
        })

def check_http_request_capabilities(content, analysis):
    """Enhanced HTTP_REQUEST analysis"""
    # Original functionality
    if re.search(r'HTTP::uri', content):
        analysis["mappable"].append({
            "feature": "URI manipulation",
            "service_policy": "HTTP URI Path Matcher in service policy rules"
        })
    
    if re.search(r'HTTP::method', content):
        analysis["mappable"].append({
            "feature": "HTTP method matching",
            "service_policy": "HTTP Method Matcher in service policy rules"
        })

    # New functionality
    # Host header manipulation
    if re.search(r'HTTP::host', content):
        analysis["mappable"].append({
            "feature": "Host header rewriting",
            "service_policy": "L7 Route configuration",
            "notes": "Configure in route settings"
        })

    # Path manipulation
    if re.search(r'HTTP::path|HTTP::uri\s+[^\s]+\s*\[', content):
        analysis["mappable"].append({
            "feature": "Path manipulation",
            "service_policy": "L7 Route path rewrite rules",
            "notes": "Available in route configuration"
        })

    # Query parameter handling
    if re.search(r'HTTP::query', content):
        analysis["mappable"].append({
            "feature": "Query parameter processing",
            "service_policy": "Query parameter matching in routes"
        })

def check_http_request_data_capabilities(content, analysis):
    """Enhanced HTTP_REQUEST_DATA analysis"""
    if re.search(r'HTTP::collect|HTTP::payload', content):
        analysis["alternatives"].append({
            "feature": "Request payload inspection",
            "alternative": "WAF policies or NGINX service chaining",
            "notes": "Use WAF for payload inspection or chain with NGINX"
        })

def check_http_response_capabilities(content, analysis):
    """Enhanced HTTP_RESPONSE analysis"""
    # Header manipulation
    if re.search(r'HTTP::header', content):
        analysis["mappable"].append({
            "feature": "Response header manipulation",
            "service_policy": "Response Headers Action in service policy"
        })
    
    # Status code handling
    if re.search(r'HTTP::status', content):
        analysis["mappable"].append({
            "feature": "Response status modification",
            "service_policy": "Custom error responses and status codes"
        })

    # HSTS and security headers
    if re.search(r'Strict-Transport-Security|X-Frame-Options|Content-Security-Policy', content):
        analysis["mappable"].append({
            "feature": "Security Headers",
            "service_policy": "Load Balancer security settings",
            "notes": "Configure security headers in LB settings"
        })

def check_clientssl_handshake_capabilities(content, analysis):
    """Enhanced SSL/TLS analysis"""
    # SSL/TLS Info
    if re.search(r'SSL::cipher', content):
        analysis["mappable"].append({
            "feature": "SSL/TLS Information",
            "service_policy": "Available in XC logs",
            "notes": "SSL details automatically logged"
        })

    # SSL Session handling
    if re.search(r'SSL::sessionid', content):
        analysis["alternatives"].append({
            "feature": "SSL Session Persistence",
            "alternative": "Load Balancer persistence settings",
            "notes": "Configure appropriate persistence method"
        })

def check_lb_selected_capabilities(content, analysis):
    """Enhanced load balancing analysis"""
    # Dynamic pool selection
    if re.search(r'pool\s+[^\s]+', content):
        analysis["mappable"].append({
            "feature": "Dynamic pool selection",
            "service_policy": "L7 Routes with Origin Pools",
            "notes": "Use multiple routes for traffic steering"
        })

    # Load balancing methods
    if re.search(r'LB::method|LB::mode', content):
        analysis["alternatives"].append({
            "feature": "Custom LB methods",
            "alternative": "Origin Pool load balancing settings",
            "notes": "Configure in origin pool settings"
        })

def generate_service_policy_template(analysis):
    """Enhanced service policy template generation"""
    template = {
        "metadata": {
            "name": "converted-irule-policy",
            "namespace": "your-namespace"
        },
        "spec": {
            "rules": []
        }
    }
    
    rule_counter = 0
    
    # Generate rules based on mappable features
    for feature in analysis["mappable"]:
        rule_counter += 1
        rule = {
            "name": f"rule-{rule_counter}",
            "action": "ALLOW",
            "conditions": []
        }

        # URI matching
        if "URI" in feature["service_policy"]:
            rule["conditions"].append({
                "match": {
                    "http_uri_path": {
                        "match_type": "PREFIX_MATCH",
                        "path": "/"
                    }
                }
            })

        # HTTP method matching
        elif "Method" in feature["service_policy"]:
            rule["conditions"].append({
                "match": {
                    "http_method": ["GET", "POST"]
                }
            })

        # Header manipulation
        elif "Headers" in feature["service_policy"]:
            rule["actions"] = {
                "request_headers": {
                    "add": {
                        "name": "X-Example",
                        "value": "value"
                    }
                }
            }

        # IP matching
        elif "IP Prefix" in feature["service_policy"]:
            rule["conditions"].append({
                "match": {
                    "ip_prefix_list": ["0.0.0.0/0"]
                }
            })

        template["spec"]["rules"].append(rule)
    
    return template

def extract_event_content(irule_content, event):
    """Extract event content with enhanced pattern matching"""
    pattern = rf'when\s+{event}\s*{{(.*?)}}'
    matches = re.finditer(pattern, irule_content, re.DOTALL)
    contents = []
    for match in matches:
        contents.append(match.group(1).strip())
    return '\n'.join(contents) if contents else None

# Example/test code
if __name__ == "__main__":
    test_irule = """
    when RULE_INIT {
        set static::pattern "test"
    }
    when HTTP_REQUEST {
        if { [HTTP::uri] starts_with "/api" } {
            HTTP::header insert "X-API" "true"
            pool api_pool
        }
    }
    when HTTP_RESPONSE {
        HTTP::header insert "Strict-Transport-Security" "max-age=31536000"
    }
    """
    
    result = analyze_irule(test_irule)
    print("\nAnalysis Result:")
    for category in ["mappable", "alternatives", "unsupported", "warnings", "recommendations"]:
        print(f"\n{category.upper()}:")
        for item in result[category]:
            print(f"- {item['feature']}")
            if "service_policy" in item:
                print(f"  Service Policy: {item['service_policy']}")
            if "alternative" in item:
                print(f"  Alternative: {item['alternative']}")
            if "note" in item:
                print(f"  Note: {item['note']}")
            if "notes" in item:
                print(f"  Notes: {item['notes']}")
            if "recommendation" in item:
                print(f"  Recommendation: {item['recommendation']}")
