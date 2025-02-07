from flask import Flask, render_template, request, jsonify
import paramiko
import re
import socket
import traceback
from nginx_compatibility import check_nginx_compatibility
from f5dc_compatibility import check_f5dc_compatibility
from irule_analyzer import analyze_irule, generate_service_policy_template

app = Flask(__name__)

class F5BIGIPAnalyzer:
    def __init__(self):
        pass

    def analyze(self, hostname, port, username, password):
        try:
            print(f"Attempting to connect to {hostname}:{port} as {username}")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname, port=port, username=username, password=password, timeout=10)
            print("SSH connection established successfully")

            print("Fetching virtual servers...")
            virtual_servers = self.get_virtual_servers(ssh)
            print(f"Found {len(virtual_servers)} virtual servers")

            print("Fetching pools...")
            pools = self.get_pools(ssh)
            print(f"Found {len(pools)} pools")

            print("Fetching iRules...")
            irules = self.get_irules(ssh)
            print(f"Found {len(irules)} iRules")

            print("Analyzing iRules...")
            irule_analysis = self.analyze_irules(irules)
            print("iRule analysis completed")

            print("Fetching ASM policies...")
            asm_policies = self.get_asm_policies(ssh)
            print(f"Found {len(asm_policies)} ASM policies")

            print("Fetching APM policies...")
            apm_policies = self.get_apm_policies(ssh)
            print(f"Found {len(apm_policies)} APM policies")

            print("Generating report...")
            report = self.generate_report(virtual_servers, pools, irules, irule_analysis, asm_policies, apm_policies)

            ssh.close()
            print("Analysis completed successfully")
            return report
        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials.")
            raise
        except paramiko.SSHException as ssh_exception:
            print(f"Unable to establish SSH connection: {str(ssh_exception)}")
            raise
        except socket.error as socket_error:
            print(f"Network error: {str(socket_error)}")
            raise
        except Exception as e:
            print(f"An unexpected error occurred during analysis: {str(e)}")
            raise

    def get_virtual_servers(self, ssh):
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list ltm virtual all-properties")
        return self.parse_config(stdout.read().decode())

    def get_pools(self, ssh):
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list ltm pool all-properties")
        return self.parse_config(stdout.read().decode())

    def get_irules(self, ssh):
        """Fetch iRules with their complete content"""
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list ltm rule")
        output = stdout.read().decode()
        
        irules = []
        current_rule = None
        current_content = []
        
        for line in output.split('\n'):
            if line.startswith('ltm rule '):
                if current_rule:
                    irules.append({
                        'type': 'ltm rule',
                        'name': current_rule,
                        'config': '\n'.join(current_content)
                    })
                current_rule = line.split()[2]
                current_content = [line]
            elif current_rule:
                current_content.append(line)
        
        # Add the last rule if exists
        if current_rule:
            irules.append({
                'type': 'ltm rule',
                'name': current_rule,
                'config': '\n'.join(current_content)
            })
        
        # For each iRule, get its actual content
        for irule in irules:
            stdin, stdout, stderr = ssh.exec_command(f"tmsh -q list ltm rule {irule['name']} {{ definition }}")
            definition = stdout.read().decode()
            if definition:
                irule['content'] = definition

        return irules

    def get_asm_policies(self, ssh):
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list asm policy")
        return self.parse_config(stdout.read().decode())

    def get_apm_policies(self, ssh):
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list apm policy")
        return self.parse_config(stdout.read().decode())

    def parse_config(self, config_str):
        configs = re.split(r'\n(?=ltm |asm |apm )', config_str)
        parsed_configs = []
        for config in configs:
            if config.strip():
                name = re.search(r'^(\w+\s+\w+\s+)(\S+)\s*{', config)
                if name:
                    parsed_configs.append({
                        'type': name.group(1).strip(),
                        'name': name.group(2),
                        'config': config
                    })
        return parsed_configs

    def analyze_irules(self, irules):
        """Analyze all iRules and their compatibility with service policies"""
        irule_analysis = {}
        print("\nStarting iRule analysis...")
        
        for irule in irules:
            print(f"\nAnalyzing iRule: {irule['name']}")
            try:
                # Try to extract the actual iRule content from the definition
                if 'content' in irule:
                    content = irule['content']
                    print(f"Found direct content for {irule['name']}")
                else:
                    content_match = re.search(r'definition\s*{(.*?)}', irule['config'], re.DOTALL)
                    content = content_match.group(1).strip() if content_match else ''
                    print(f"Extracted content from config for {irule['name']}")
                
                print(f"Content length: {len(content) if content else 0} characters")
                if content:
                    print("First 100 characters of content:", content[:100])
                    analysis = analyze_irule(content)
                    print(f"Analysis complete for {irule['name']}")
                    print("Found features:", {
                        "mappable": len(analysis["mappable"]),
                        "alternatives": len(analysis["alternatives"]),
                        "unsupported": len(analysis["unsupported"]),
                        "warnings": len(analysis["warnings"])
                    })
                    
                    if analysis["mappable"]:
                        analysis["service_policy_template"] = generate_service_policy_template(analysis)
                    irule_analysis[irule['name']] = analysis
                else:
                    print(f"No content found for {irule['name']}")
                    irule_analysis[irule['name']] = {
                        "mappable": [],
                        "alternatives": [],
                        "unsupported": [],
                        "warnings": ["Unable to retrieve iRule content"]
                    }
            except Exception as e:
                print(f"Error analyzing iRule {irule['name']}: {str(e)}")
                print("Full error:", traceback.format_exc())
                irule_analysis[irule['name']] = {
                    "mappable": [],
                    "alternatives": [],
                    "unsupported": [],
                    "warnings": [f"Error analyzing iRule: {str(e)}"]
                }
        
        return irule_analysis

    def get_associated_irules(self, vs_config):
        """Get list of iRules associated with a virtual server"""
        rules_match = re.search(r'rules\s*{([^}]+)}', vs_config)
        if rules_match:
            return [rule.strip() for rule in rules_match.group(1).split()]
        return []

    def generate_report(self, virtual_servers, pools, irules, irule_analysis, asm_policies, apm_policies):
        report = {
            "summary": {
                "virtual_servers": len(virtual_servers),
                "pools": len(pools),
                "irules": len(irules),
                "asm_policies": len(asm_policies),
                "apm_policies": len(apm_policies)
            },
            "virtual_servers": [],
            "irules_analysis": irule_analysis  # Add complete iRule analysis to report
        }

        for vs in virtual_servers:
            associated_irules = self.get_associated_irules(vs['config'])
            
            vs_report = {
                "name": vs['name'],
                "destination": self.extract_destination(vs['config']),
                "pool": self.extract_pool(vs['config']),
                "pool_members": self.get_pool_members(vs['config'], pools),
                "irules": associated_irules,
                "irules_analysis": {  # Add analysis for associated iRules
                    irule: irule_analysis.get(irule, {})
                    for irule in associated_irules
                },
                "nginx_compatibility": check_nginx_compatibility(vs['config']),
                "f5dc_compatibility": check_f5dc_compatibility(vs['config'])
            }
            report["virtual_servers"].append(vs_report)

        return report

    def extract_destination(self, config):
        dest_match = re.search(r'destination\s+(\S+)', config)
        return dest_match.group(1) if dest_match else "Not specified"

    def extract_pool(self, config):
        pool_match = re.search(r'\n\s*pool\s+(\S+)', config)
        return pool_match.group(1) if pool_match else "None"

    def get_pool_members(self, vs_config, pools):
        pool_name = self.extract_pool(vs_config)
        if pool_name == "None":
            return []
        pool_config = next((p for p in pools if p['name'] == pool_name), None)
        if not pool_config:
            return []
        members = re.findall(r'(\S+):\S+\s*{\s*address\s+(\S+)', pool_config['config'])
        return [{"name": m[0], "address": m[1]} for m in members]

analyzer = F5BIGIPAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        hostname = request.form['hostname']
        port = int(request.form['port'])
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
