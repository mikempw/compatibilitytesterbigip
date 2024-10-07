import re

def check_f5dc_compatibility(config):
    incompatible_features = [
        'asp', 'sip', 'rtsp', 'diameter', 'radius'
    ]

    lb_method = get_load_balancing_method(config)
    incompatible_lb_methods = [
        'ratio-member', 'ratio-node', 'ratio-session', 'weighted-least-connections-node',
        'observed-member', 'predictive-member', 'ratio-least-connections-member',
        'ratio-least-connections-node'
    ]
    
    incompatibilities = []

    if lb_method in incompatible_lb_methods:
        incompatibilities.append(f"Incompatible load balancing method: {lb_method}")

    if has_hardware_features(config):
        incompatibilities.append("Uses hardware-specific features")

    for feature in incompatible_features:
        if feature in config.lower():
            incompatibilities.append(f"Uses incompatible feature: {feature}")

    return incompatibilities

def get_load_balancing_method(config):
    lb_match = re.search(r'load-balancing-mode\s+(\S+)', config)
    return lb_match.group(1) if lb_match else None

def has_hardware_features(config):
    hardware_features = [
        'hardware-syncookie', 'hardware-syncookie-enabled',
        'hw-acceleration', 'hardware-acceleration',
        'fpga', 'tmc', 'tm.hardware'
    ]
    return any(feature in config.lower() for feature in hardware_features)