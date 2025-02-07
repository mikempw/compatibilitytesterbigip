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
    
    # Common iRule events and their service policy equivalents
    events = {
        'HTTP_REQUEST': check_http_request_capabilities,
        'HTTP_RESPONSE': check_http_response_capabilities,
        'CLIENT_ACCEPTED': check_client_accepted_capabilities,
        'SERVER_CONNECTED': check_server_connected_capabilities,
        'RULE_INIT': check_rule_init_capabilities
    }
    
    # Extract and analyze each event
    for event, checker in events.items():
        if re.search(rf'when\s+{event}\s*{{', irule_content, re.IGNORECASE):
            event_content = extract_event_content(irule_content, event)
            if event_content:
                checker(event_content, analysis)
    
    return analysis

def extract_event_content(irule_content, event):
    """Extract the content within a specific event block"""
    pattern = rf'when\s+{event}\s*{{(.*?)}}'
    match = re.search(pattern, irule_content, re.DOTALL)
    return match.group(1) if match else None

def check_http_request_capabilities(content, analysis):
    """Analyze HTTP_REQUEST event content"""
    
    # URI matching and manipulation
    if re.search(r'HTTP::uri', content):
        analysis["mappable"].append({
            "feature": "URI matching/manipulation",
            "service_policy": "HTTP URI Path Matcher in service policy rules"
        })
    
    # HTTP method matching
    if re.search(r'HTTP::method', content):
        analysis["mappable"].append({
            "feature": "HTTP method matching",
            "service_policy": "HTTP Method Matcher in service policy rules"
        })
    
    # Header manipulation
    if re.search(r'HTTP::header', content):
        analysis["mappable"].append({
            "feature": "HTTP header manipulation",
            "service_policy": "Request Headers Matcher/Action in service policy"
        })
    
    # IP address matching
    if re.search(r'IP::client_addr|IP::local_addr', content):
        analysis["mappable"].append({
            "feature": "IP address matching",
            "service_policy": "IP Prefix List Matcher in service policy"
        })
    
    # HTTP::redirect
    if re.search(r'HTTP::redirect', content):
        analysis["mappable"].append({
            "feature": "HTTP redirects",
            "service_policy": "HTTP Response Action with redirect configuration"
        })
    
    # pool selection
    if re.search(r'pool\s+[^\s]+', content):
        analysis["alternatives"].append({
            "feature": "Dynamic pool selection",
            "alternative": "Use Origin Pools with Load Balancer rules"
        })
    
    # Complex string manipulation
    if re.search(r'(regexp|regsub|substr|replace)', content):
        analysis["warnings"].append({
            "feature": "Complex string manipulation",
            "note": "May require careful review and custom implementation"
        })
    
    # TCL variables and control structures
    if re.search(r'(set|if|foreach|switch|while)', content):
        analysis["warnings"].append({
            "feature": "TCL programming constructs",
            "note": "May need to be reimplemented using multiple service policy rules"
        })

def check_http_response_capabilities(content, analysis):
    """Analyze HTTP_RESPONSE event content"""
    
    # Response header manipulation
    if re.search(r'HTTP::header', content):
        analysis["mappable"].append({
            "feature": "Response header manipulation",
            "service_policy": "Response Headers Action in service policy"
        })
    
    # Response body manipulation
    if re.search(r'HTTP::payload', content):
        analysis["unsupported"].append({
            "feature": "Response body manipulation",
            "note": "Not directly supported in service policies"
        })
    
    # Response cookie manipulation
    if re.search(r'HTTP::cookie', content):
        analysis["alternatives"].append({
            "feature": "Cookie manipulation",
            "alternative": "Use Request/Response Headers actions for basic cookie handling"
        })

def check_client_accepted_capabilities(content, analysis):
    """Analyze CLIENT_ACCEPTED event content"""
    
    # TCP optimization
    if re.search(r'TCP::', content):
        analysis["unsupported"].append({
            "feature": "TCP level optimizations",
            "note": "TCP-level controls not available in service policies"
        })
    
    # Client-side SSL
    if re.search(r'SSL::', content):
        analysis["alternatives"].append({
            "feature": "SSL/TLS handling",
            "alternative": "Configure SSL/TLS settings in Load Balancer configuration"
        })

def check_server_connected_capabilities(content, analysis):
    """Analyze SERVER_CONNECTED event content"""
    
    # Server-side SSL
    if re.search(r'SSL::', content):
        analysis["alternatives"].append({
            "feature": "Server-side SSL/TLS",
            "alternative": "Configure backend SSL/TLS in Origin Pool settings"
        })
    
    # Server-side TCP
    if re.search(r'TCP::', content):
        analysis["unsupported"].append({
            "feature": "Server-side TCP controls",
            "note": "TCP-level controls not available for backend connections"
        })

def check_rule_init_capabilities(content, analysis):
    """Analyze RULE_INIT event content"""
    
    # Static variables
    if re.search(r'set\s+static::', content):
        analysis["alternatives"].append({
            "feature": "Static variable initialization",
            "alternative": "Consider using Custom Metadata in service policies"
        })
    
    # Table usage
    if re.search(r'table\s+set', content):
        analysis["unsupported"].append({
            "feature": "iRule tables",
            "note": "No direct equivalent for persistent tables"
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
    
    # Add rules based on mappable features
    for feature in analysis["mappable"]:
        if "HTTP URI Path Matcher" in feature["service_policy"]:
            template["spec"]["rules"].append({
                "name": "uri-matching-rule",
                "match": {
                    "http_uri_path": {
                        "match_type": "PREFIX_MATCH",
                        "path": "/"
                    }
                }
            })
        # Add more rule templates based on other mappable features
    
    return template
