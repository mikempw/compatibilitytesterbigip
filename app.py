from flask import Flask, render_template, request, jsonify
import requests
import traceback
import urllib3
from nginx_compatibility import check_nginx_compatibility
from f5dc_compatibility import check_f5dc_compatibility

# Disable SSL warnings - in production, you'd want to handle this properly
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

class F5BIGIPAnalyzer:
    def __init__(self):
        self.api_base = None
        self.session = None

    def analyze(self, hostname, port, username, password):
        try:
            # Set up the REST API connection
            self.api_base = f"https://{hostname}:{port}/mgmt/tm"
            self.session = requests.Session()
            self.session.auth = (username, password)
            self.session.verify = False  # In production, use proper certificate verification
            
            # Test connection
            print(f"Attempting to connect to {hostname}:{port} as {username}")
            response = self.session.get(f"{self.api_base}/sys/version")
            response.raise_for_status()
            print("REST API connection established successfully")
            
            # Check if bash utility is available (for advanced configuration fetching)
            try:
                bash_test = self.session.post(
                    f"https://{hostname}:{port}/mgmt/tm/util/bash",
                    json={"command": "run", "utilCmdArgs": "-c 'echo test'"}
                )
                bash_test.raise_for_status()
                print("Bash utility available for advanced configuration fetching")
            except Exception as e:
                print(f"Warning: Bash utility not available - falling back to API-only mode: {str(e)}")
            
            # Fetch configuration components
            print("Fetching virtual servers...")
            virtual_servers = self.get_virtual_servers()
            print(f"Found {len(virtual_servers)} virtual servers")
            
            print("Fetching pools...")
            pools = self.get_pools()
            print(f"Found {len(pools)} pools")
            
            print("Fetching iRules...")
            irules = self.get_irules()
            print(f"Found {len(irules)} iRules")
            
            print("Fetching ASM policies...")
            asm_policies = self.get_asm_policies()
            print(f"Found {len(asm_policies)} ASM policies")
            
            print("Fetching APM policies...")
            apm_policies = self.get_apm_policies()
            print(f"Found {len(apm_policies)} APM policies")
            
            print("Generating report...")
            report = self.generate_report(virtual_servers, pools, irules, asm_policies, apm_policies)
            
            print("Analysis completed successfully")
            return report
            
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error: {http_err}")
            raise
        except requests.exceptions.ConnectionError as conn_err:
            print(f"Connection error: {conn_err}")
            raise
        except requests.exceptions.Timeout as timeout_err:
            print(f"Timeout error: {timeout_err}")
            raise
        except requests.exceptions.RequestException as req_err:
            print(f"Request error: {req_err}")
            raise
        except Exception as e:
            print(f"An unexpected error occurred during analysis: {str(e)}")
            raise

    def get_virtual_servers(self):
        response = self.session.get(f"{self.api_base}/ltm/virtual?expandSubcollections=true")
        response.raise_for_status()
        data = response.json()
        
        virtual_servers = []
        for item in data.get('items', []):
            # Get full configuration in tmsh format for compatibility checks
            vs_name = item.get('fullPath', item.get('name', ''))
            try:
                # Get the full tmsh formatted configuration for better compatibility checks
                cmd_response = self.session.post(
                    f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                    json={
                        "command": "run",
                        "utilCmdArgs": f"-c 'tmsh -q list ltm virtual {vs_name} all-properties'"
                    }
                )
                cmd_response.raise_for_status()
                config_str = cmd_response.json().get('commandResult', '')
            except Exception as e:
                print(f"Warning: Could not get tmsh configuration for {vs_name}: {str(e)}")
                config_str = str(item)  # Fallback to JSON string representation
                
            virtual_servers.append({
                'type': 'ltm virtual',
                'name': item.get('name', ''),
                'config': config_str,
                'raw_data': item
            })
        return virtual_servers

    def get_pools(self):
        response = self.session.get(f"{self.api_base}/ltm/pool?expandSubcollections=true")
        response.raise_for_status()
        data = response.json()
        
        pools = []
        for item in data.get('items', []):
            pool_name = item.get('fullPath', item.get('name', ''))
            try:
                # Get the full tmsh formatted configuration
                cmd_response = self.session.post(
                    f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                    json={
                        "command": "run",
                        "utilCmdArgs": f"-c 'tmsh -q list ltm pool {pool_name} all-properties'"
                    }
                )
                cmd_response.raise_for_status()
                config_str = cmd_response.json().get('commandResult', '')
            except Exception as e:
                print(f"Warning: Could not get tmsh configuration for pool {pool_name}: {str(e)}")
                config_str = str(item)  # Fallback to JSON string representation
                
            pools.append({
                'type': 'ltm pool',
                'name': item.get('name', ''),
                'config': config_str,
                'raw_data': item
            })
        return pools

    def get_irules(self):
        response = self.session.get(f"{self.api_base}/ltm/rule")
        response.raise_for_status()
        data = response.json()
        
        irules = []
        for item in data.get('items', []):
            irule_name = item.get('fullPath', item.get('name', ''))
            try:
                # Get the full tmsh formatted configuration
                cmd_response = self.session.post(
                    f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                    json={
                        "command": "run",
                        "utilCmdArgs": f"-c 'tmsh -q list ltm rule {irule_name}'"
                    }
                )
                cmd_response.raise_for_status()
                config_str = cmd_response.json().get('commandResult', '')
            except Exception as e:
                print(f"Warning: Could not get tmsh configuration for iRule {irule_name}: {str(e)}")
                config_str = str(item)  # Fallback to JSON string representation
                
            irules.append({
                'type': 'ltm rule',
                'name': item.get('name', ''),
                'config': config_str,
                'raw_data': item
            })
        return irules

    def get_asm_policies(self):
        try:
            response = self.session.get(f"{self.api_base}/asm/policies")
            response.raise_for_status()
            data = response.json()
            
            asm_policies = []
            for item in data.get('items', []):
                config_str = str(item)
                asm_policies.append({
                    'type': 'asm policy',
                    'name': item.get('name', ''),
                    'config': config_str,
                    'raw_data': item
                })
            return asm_policies
        except requests.exceptions.HTTPError:
            # ASM might not be enabled on this F5
            print("Note: ASM module might not be enabled")
            return []

    def get_apm_policies(self):
        try:
            response = self.session.get(f"{self.api_base}/apm/policy")
            response.raise_for_status()
            data = response.json()
            
            apm_policies = []
            for item in data.get('items', []):
                config_str = str(item)
                apm_policies.append({
                    'type': 'apm policy',
                    'name': item.get('name', ''),
                    'config': config_str,
                    'raw_data': item
                })
            return apm_policies
        except requests.exceptions.HTTPError:
            # APM might not be enabled on this F5
            print("Note: APM module might not be enabled")
            return []

    def generate_report(self, virtual_servers, pools, irules, asm_policies, apm_policies):
        report = {
            "summary": {
                "virtual_servers": len(virtual_servers),
                "pools": len(pools),
                "irules": len(irules),
                "asm_policies": len(asm_policies),
                "apm_policies": len(apm_policies)
            },
            "virtual_servers": []
        }

        for vs in virtual_servers:
            vs_report = {
                "name": vs['name'],
                "destination": self.extract_destination(vs),
                "pool": self.extract_pool(vs),
                "pool_members": self.get_pool_members(vs, pools),
                "irules": self.extract_irules(vs),
                "nginx_compatibility": check_nginx_compatibility(vs['config']),
                "f5dc_compatibility": check_f5dc_compatibility(vs['config'])
            }
            report["virtual_servers"].append(vs_report)

        return report

    def extract_destination(self, vs):
        raw_data = vs.get('raw_data', {})
        if 'destination' in raw_data:
            # The destination in API response might be in the format of '/partition/address:port'
            destination = raw_data['destination']
            if isinstance(destination, str):
                return destination
            elif isinstance(destination, dict) and 'name' in destination:
                return destination['name']
        return "Not specified"

    def extract_pool(self, vs):
        raw_data = vs.get('raw_data', {})
        if 'pool' in raw_data:
            pool = raw_data['pool']
            if isinstance(pool, str):
                return pool
            elif isinstance(pool, dict) and 'name' in pool:
                return pool['name']
        return "None"

    def get_pool_members(self, vs, pools):
        pool_name = self.extract_pool(vs)
        if pool_name == "None":
            return []
            
        pool_config = next((p for p in pools if p['name'] == pool_name), None)
        if not pool_config:
            return []
            
        pool_data = pool_config.get('raw_data', {})
        members = []
        
        # Members are typically in a subcollection named 'membersReference'
        members_ref = pool_data.get('membersReference', {})
        if 'items' in members_ref:
            for member in members_ref.get('items', []):
                member_name = member.get('name', '')
                address = ''
                
                # Try to extract address from 'address' field
                if 'address' in member:
                    address = member['address']
                # Alternatively, the name might already be in format 'name:port'
                elif ':' in member_name:
                    address = member_name.split(':')[0]
                    
                members.append({
                    "name": member_name,
                    "address": address
                })
                
        return members

    def extract_irules(self, vs):
        raw_data = vs.get('raw_data', {})
        if 'rules' in raw_data:
            rules = raw_data['rules']
            return rules if isinstance(rules, list) else []
        return []

analyzer = F5BIGIPAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        hostname = request.form['hostname']
        port = request.form.get('port', 443)  # Default to HTTPS port
        username = request.form['username']
        password = request.form['password']

        results = analyzer.analyze(hostname, port, username, password)
        return jsonify(results)
    except Exception as e:
        error_traceback = traceback.format_exc()
        app.logger.error(f"An error occurred:\n{error_traceback}")
        return jsonify({"error": str(e), "traceback": error_traceback}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
