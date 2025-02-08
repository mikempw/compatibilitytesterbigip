import re

def analyze_irule(irule_content):
    """
    Analyzes an iRule and determines compatibility with F5 Distributed Cloud service policies.
    Returns mappable features, alternatives needed, and unsupported features.
    """
    analysis = {
        "mappable": [],        # Can be directly mapped to service policies
        "alternatives": [],     # Requires alternative implementation
        "unsupported": [],     # Currently not possible in XC
        "warnings": []         # Additional considerations
    }
    
    print(f"Starting iRule content analysis...")
    
    # Check for session tracking
    if re.search(r'CLIENT_ACCEPTED.*?IP::client_addr', irule_content, re.DOTALL):
        analysis["mappable"].append({
            "feature": "Client IP tracking",
            "service_policy": "Client IP match conditions in service policy"
        })
    
    # Check for table operations
    if re.search(r'table\s+(set|lookup|delete)', irule_content):
        analysis["alternatives"].append({
            "feature": "Table operations for state management",
            "alternative": "Consider using distributed key-value store or custom metadata"
        })
    
    # Check for pattern matching and redirects
    if re.search(r'regexp|string\s+match', irule_content):
        analysis["mappable"].append({
            "feature": "Pattern matching",
            "service_policy": "Regular expression matching in service policy rules"
        })
    
    if re.search(r'HTTP::redirect', irule_content):
        analysis["mappable"].append({
            "feature": "HTTP redirects",
            "service_policy": "HTTP redirect actions in service policy"
        })
    
    # Check for data collection
    if re.search(r'HTTP::collect', irule_content):
        analysis["alternatives"].append({
            "feature": "Request/Response data collection",
            "alternative": "Consider using WAF policies or custom rules for payload inspection"
        })
    
    # Check for header manipulation
    if re.search(r'HTTP::header\s+(insert|remove)', irule_content):
        analysis["mappable"].append({
            "feature": "Header manipulation",
            "service_policy": "Request/Response header actions in service policy"
        })
    
    # Check for response handling
    if 'HTTP_RESPONSE' in irule_content:
        analysis["mappable"].append({
            "feature": "Response processing",
            "service_policy": "Response phase actions in service policy"
        })
    
    # Check for complex flow control
    if re.search(r'(if|switch|foreach|while)', irule_content):
        analysis["warnings"].append({
            "feature": "Complex flow control",
            "note": "May require multiple service policy rules and careful logic restructuring"
        })
    
    # Check for static variable initialization
    if re.search(r'set\s+static::', irule_content):
        analysis["alternatives"].append({
            "feature": "Static variable initialization",
            "alternative": "Consider using system metadata or configuration"
        })
    
    # Check for memory/buffer management
    if re.search(r'string\s+range|string\s+length', irule_content):
        analysis["warnings"].append({
            "feature": "Memory/buffer management",
            "note": "Consider request/response size limits in Load Balancer configuration"
        })
    
    # Check for TCP/IP level operations
    if re.search(r'TCP::|IP::', irule_content):
        analysis["alternatives"].append({
            "feature": "TCP/IP level operations",
            "alternative": "Use Load Balancer TCP/UDP settings and service policies where applicable"
        })
    
    # Check for error handling
    if re.search(r'catch\s*{', irule_content):
        analysis["warnings"].append({
            "feature": "TCL error handling",
            "note": "Implement appropriate error handling in service policies and monitoring"
        })
    
    # Check for logging
    if re.search(r'log\s+local', irule_content):
        analysis["alternatives"].append({
            "feature": "Local logging",
            "alternative": "Configure appropriate logging in XC monitoring and alerts"
        })
    
    # Check for specific event handlers
    events = {
        'HTTP_REQUEST': check_http_request_capabilities,
        'HTTP_RESPONSE': check_http_response_capabilities,
        'CLIENT_ACCEPTED': check_client_accepted_capabilities,
        'SERVER_CONNECTED': check_server_connected_capabilities,
        'RULE_INIT': check_rule_init_capabilities,
        'HTTP_REQUEST_DATA': check_http_request_data_capabilities,
        'HTTP_RESPONSE_DATA': check_http_response_data_capabilities
    }
    
    for event, checker in events.items():
        if re.search(rf'when\s+{event}\s*{{', irule_content, re.IGNORECASE):
            event_content = extract_event_content(irule_content, event)
            if event_content:
                checker(event_content, analysis)
    
    return analysis

def extract_event_content(irule_content, event):
    """Extract the content within a specific event block"""
    pattern = rf'when\s+{event}\s*{{(.*?)}}'
    matches = re.finditer(pattern, irule_content, re.DOTALL)
    contents = []
    for match in matches:
        contents.append(match.group(1))
    return '\n'.join(contents) if contents else None

def check_http_request_capabilities(content, analysis):
    """Analyze HTTP_REQUEST event content"""
    
    # URI manipulation
    if re.search(r'HTTP::uri', content):
        analysis["mappable"].append({
            "feature": "URI manipulation",
            "service_policy": "HTTP URI Path Matcher in service policy rules"
        })
    
    # Query parameter handling
    if re.search(r'HTTP::query', content):
        analysis["mappable"].append({
            "feature": "Query parameter processing",
            "service_policy": "Query parameter matching in service policy"
        })
    
    # Custom content routing
    if re.search(r'pool\s+\S+', content):
        analysis["alternatives"].append({
            "feature": "Custom content routing",
            "alternative": "Use Load Balancer rules and origin pools"
        })

def check_http_request_data_capabilities(content, analysis):
    """Analyze HTTP_REQUEST_DATA event content"""
    if re.search(r'HTTP::payload', content):
        analysis["alternatives"].append({
            "feature": "Request payload inspection",
            "alternative": "Use WAF policies or custom security rules"
        })

def check_http_response_capabilities(content, analysis):
    """Analyze HTTP_RESPONSE event content"""
    
    # Response header manipulation
    if re.search(r'HTTP::header', content):
        analysis["mappable"].append({
            "feature": "Response header manipulation",
            "service_policy": "Response Headers Action in service policy"
        })
    
    # Response payload modification
    if re.search(r'HTTP::payload', content):
        analysis["unsupported"].append({
            "feature": "Response payload modification",
            "note": "Response body modification not directly supported"
        })

def check_http_response_data_capabilities(content, analysis):
    """Analyze HTTP_RESPONSE_DATA event content"""
    if re.search(r'HTTP::payload', content):
        analysis["unsupported"].append({
            "feature": "Response data manipulation",
            "note": "Response payload modification not supported"
        })

def check_client_accepted_capabilities(content, analysis):
    """Analyze CLIENT_ACCEPTED event content"""
    
    # Client-side connection handling
    if re.search(r'TCP::|IP::', content):
        analysis["alternatives"].append({
            "feature": "Client connection handling",
            "alternative": "Use Load Balancer TCP/UDP settings"
        })

def check_server_connected_capabilities(content, analysis):
    """Analyze SERVER_CONNECTED event content"""
    
    # Server-side connection handling
    if re.search(r'TCP::|IP::', content):
        analysis["alternatives"].append({
            "feature": "Server connection handling",
            "alternative": "Configure in origin pool settings"
        })

def check_rule_init_capabilities(content, analysis):
    """Analyze RULE_INIT event content"""
    
    # Static variables
    if re.search(r'set\s+static::', content):
        analysis["alternatives"].append({
            "feature": "Static variable initialization",
            "alternative": "Use system metadata or configuration"
        })
    
    # Regular expressions
    if re.search(r'regexp|regex', content):
        analysis["mappable"].append({
            "feature": "Regular expression patterns",
            "service_policy": "Regular expression matching in rules"
        })

def generate_service_policy_template(analysis):
    """
    Generates a sample service policy template based on the analysis results
    """
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
    
    # Add rules based on mappable features
    for feature in analysis["mappable"]:
        rule_counter += 1
        rule = {
            "name": f"rule-{rule_counter}",
            "action": "ALLOW",
            "conditions": []
        }
        
        if "URI" in feature["service_policy"]:
            rule["conditions"].append({
                "type": "URI_PATH",
                "pattern": "/*"
            })
        
        if "header" in feature["service_policy"].lower():
            rule["actions"] = {
                "headers": {
                    "add": {
                        "name": "X-Example",
                        "value": "value"
                    }
                }
            }
        
        if "redirect" in feature["service_policy"].lower():
            rule["action"] = "REDIRECT"
            rule["redirect"] = {
                "protocol": "HTTPS",
                "port": 443
            }
        
        template["spec"]["rules"].append(rule)
    
    return template

# Example usage
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
    """
    
    result = analyze_irule(test_irule)
    print("\nAnalysis Result:")
    for category in ["mappable", "alternatives", "unsupported", "warnings"]:
        print(f"\n{category.upper()}:")
        for item in result[category]:
            print(f"- {item['feature']}")
            if "service_policy" in item:
                print(f"  Service Policy: {item['service_policy']}")
            if "alternative" in item:
                print(f"  Alternative: {item['alternative']}")
            if "note" in item:
                print(f"  Note: {item['note']}")
