from flask import Flask, render_template, request, jsonify
from app.metrics.metrics_handler import MetricsHandler
import paramiko
import re
import socket
import traceback
import warnings
from nginx_compatibility import check_nginx_compatibility
from f5dc_compatibility import check_f5dc_compatibility
from irule_analyzer import analyze_irule, generate_service_policy_template
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize metrics handler
metrics = MetricsHandler()

class F5BIGIPAnalyzer:
    def __init__(self):
        pass

    def analyze(self, hostname, port, username, password):
        try:
            logger.info(f"Attempting to connect to {hostname}:{port} as {username}")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname, port=port, username=username, password=password, timeout=10)
            logger.info("SSH connection established successfully")

            logger.info("Fetching virtual servers...")
            virtual_servers = self.get_virtual_servers(ssh)
            logger.info(f"Found {len(virtual_servers)} virtual servers")

            logger.info("Fetching pools...")
            pools = self.get_pools(ssh)
            logger.info(f"Found {len(pools)} pools")

            logger.info("Fetching iRules...")
            irules = self.get_irules(ssh)
            logger.info(f"Found {len(irules)} iRules")

            logger.info("Analyzing iRules...")
            irule_analysis = self.analyze_irules(irules)
            logger.info("iRule analysis completed")

            logger.info("Fetching ASM policies...")
            asm_policies = self.get_asm_policies(ssh)
            logger.info(f"Found {len(asm_policies)} ASM policies")

            logger.info("Fetching APM policies...")
            apm_policies = self.get_apm_policies(ssh)
            logger.info(f"Found {len(apm_policies)} APM policies")

            logger.info("Checking HTTP profile settings...")
            http_settings = self.get_http_settings(ssh)
            logger.info("HTTP settings retrieved")

            logger.info("Generating report...")
            report = self.generate_report(
                virtual_servers, 
                pools, 
                irules, 
                irule_analysis, 
                asm_policies, 
                apm_policies,
                http_settings
            )

            ssh.close()
            logger.info("Analysis completed successfully")

            # Update metrics if enabled
            if metrics.enabled:
                for vs in virtual_servers:
                    vs_name = vs.get('name', 'unknown')
                    vs_ip = self.extract_destination(vs.get('config', ''))
                    vs_analysis = report.get('virtual_servers', {})
                    
                    for vs_details in vs_analysis:
                        if vs_details.get('name') == vs_name:
                            metrics.update_metrics(vs_details, vs_name, vs_ip)

            return report

        except paramiko.AuthenticationException:
            logger.error("Authentication failed")
            raise
        except paramiko.SSHException as ssh_exception:
            logger.error(f"SSH connection failed: {str(ssh_exception)}")
            raise
        except socket.error as socket_error:
            logger.error(f"Network error: {str(socket_error)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    def get_virtual_servers(self, ssh):
        """Fetch all virtual servers with their complete configuration"""
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list ltm virtual all-properties")
        return self.parse_config(stdout.read().decode())

    def get_pools(self, ssh):
        """Fetch all pools with their complete configuration"""
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list ltm pool all-properties")
        return self.parse_config(stdout.read().decode())

    def get_irules(self, ssh):
        """Fetch iRules with their complete content"""
        logger.info("Getting iRules list...")
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list ltm rule")
        base_output = stdout.read().decode()
        logger.info(f"Base iRule output received")
        
        irules = []
        rule_names = []
        for line in base_output.split('\n'):
            if line.startswith('ltm rule '):
                rule_name = line.split()[2]
                rule_names.append(rule_name)
                logger.info(f"Found iRule: {rule_name}")

        for rule_name in rule_names:
            logger.info(f"Getting content for iRule: {rule_name}")
            stdin, stdout, stderr = ssh.exec_command(f"tmsh -q list ltm rule {rule_name}")
            rule_content = stdout.read().decode()
            logger.info(f"Content length: {len(rule_content)}")
            
            if rule_content:
                definition_match = re.search(r'definition\s*{([^}]+)}', rule_content, re.DOTALL)
                if definition_match:
                    irule_def = definition_match.group(1).strip()
                    logger.info(f"Extracted iRule definition for {rule_name}")
                else:
                    irule_def = ""
                    logger.info(f"No definition found for {rule_name}")

                irules.append({
                    'type': 'ltm rule',
                    'name': rule_name,
                    'config': rule_content,
                    'content': irule_def
                })
            else:
                logger.info(f"No content found for {rule_name}")

        logger.info(f"Total iRules processed: {len(irules)}")
        return irules

    def get_asm_policies(self, ssh):
        """Fetch ASM policies"""
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list asm policy")
        return self.parse_config(stdout.read().decode())

    def get_apm_policies(self, ssh):
        """Fetch APM policies"""
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list apm policy")
        return self.parse_config(stdout.read().decode())

    def get_http_settings(self, ssh):
        """Fetch HTTP profile settings"""
        stdin, stdout, stderr = ssh.exec_command("tmsh -q show /ltm profile http")
        return stdout.read().decode()

    def parse_config(self, config_str):
        """Parse BIG-IP configuration into structured format"""
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
        logger.info("\nStarting iRule analysis...")
        logger.info(f"Total iRules to analyze: {len(irules)}")
        
        for irule in irules:
            logger.info(f"\nAnalyzing iRule: {irule['name']}")
            try:
                logger.info(f"iRule content type: {type(irule.get('content'))}")
                
                content = irule.get('content', '')
                if not content:
                    logger.info(f"No direct content, extracting from config")
                    content = irule.get('config', '')
                
                logger.info(f"Content length: {len(content) if content else 0} characters")
                if content:
                    logger.debug("First 200 characters of content:", content[:200])
                    analysis = analyze_irule(content)
                    logger.info(f"Analysis complete for {irule['name']}")
                    logger.info("Found features:", {
                        "mappable": len(analysis["mappable"]),
                        "alternatives": len(analysis["alternatives"]),
                        "unsupported": len(analysis["unsupported"]),
                        "warnings": len(analysis["warnings"])
                    })
                    
                    if analysis["mappable"]:
                        analysis["service_policy_template"] = generate_service_policy_template(analysis)
                    irule_analysis[irule['name']] = analysis
                else:
                    logger.warning(f"No content found for {irule['name']}")
                    irule_analysis[irule['name']] = {
                        "mappable": [],
                        "alternatives": [],
                        "unsupported": [],
                        "warnings": ["Unable to retrieve iRule content"]
                    }
            except Exception as e:
                logger.error(f"Error analyzing iRule {irule['name']}: {str(e)}")
                logger.error(traceback.format_exc())
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

    def extract_destination(self, config):
        """Extract destination information from virtual server config"""
        dest_match = re.search(r'destination\s+(\S+)', config)
        return dest_match.group(1) if dest_match else "Not specified"

    def extract_pool(self, config):
        """Extract pool information from virtual server config"""
        pool_match = re.search(r'\n\s*pool\s+(\S+)', config)
        return pool_match.group(1) if pool_match else "None"

    def get_pool_members(self, vs_config, pools):
        """Get pool members for a virtual server"""
        pool_name = self.extract_pool(vs_config)
        if pool_name == "None":
            return []
        pool_config = next((p for p in pools if p['name'] == pool_name), None)
        if not pool_config:
            return []
        members = re.findall(r'(\S+):\S+\s*{\s*address\s+(\S+)', pool_config['config'])
        return [{"name": m[0], "address": m[1]} for m in members]

    def extract_ssl_profiles(self, config):
        """Extract SSL profile information from virtual server config"""
        ssl_profiles = []
        profiles_match = re.search(r'profiles\s*{([^}]+)}', config)
        if profiles_match:
            profile_content = profiles_match.group(1)
            clientssl_matches = re.finditer(r'(\S+)\s*{\s*context\s+clientside', profile_content)
            serverssl_matches = re.finditer(r'(\S+)\s*{\s*context\s+serverside', profile_content)
            
            ssl_profiles.extend([{"name": m.group(1), "type": "clientssl"} for m in clientssl_matches])
            ssl_profiles.extend([{"name": m.group(1), "type": "serverssl"} for m in serverssl_matches])
        
        return ssl_profiles if ssl_profiles else None

    def extract_persistence(self, config):
        """Extract persistence information from virtual server config"""
        persist_match = re.search(r'persist\s*{([^}]+)}', config)
        if persist_match:
            persist_content = persist_match.group(1)
            persist_type = re.search(r'(\S+)\s*{', persist_content)
            return persist_type.group(1) if persist_type else None
        return None

    def generate_report(self, virtual_servers, pools, irules, irule_analysis, asm_policies, apm_policies, http_settings):
        """Generate comprehensive analysis report"""
        report = {
            "summary": {
                "virtual_servers": len(virtual_servers),
                "pools": len(pools),
                "irules": len(irules),
                "asm_policies": len(asm_policies),
                "apm_policies": len(apm_policies)
            },
            "virtual_servers": [],
            "irules_analysis": irule_analysis,
            "http_settings": http_settings
        }

        for vs in virtual_servers:
            associated_irules = self.get_associated_irules(vs['config'])
            
            vs_report = {
                "name": vs['name'],
                "destination": self.extract_destination(vs['config']),
                "pool": self.extract_pool(vs['config']),
                "pool_members": self.get_pool_members(vs['config'], pools),
                "irules": associated_irules,
                "irules_analysis": {
                    irule: irule_analysis.get(irule, {})
                    for irule in associated_irules
                },
                "nginx_compatibility": check_nginx_compatibility(vs['config']),
                "f5dc_compatibility": check_f5dc_compatibility(vs['config'])
            }
            
            ssl_profiles = self.extract_ssl_profiles(vs['config'])
            if ssl_profiles:
                vs_report["ssl_profiles"] = ssl_profiles

            persistence = self.extract_persistence(vs['config'])
            if persistence:
                vs_report["persistence"] = persistence

            report["virtual_servers"].append(vs_report)

        return report

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
        logger.error(f"An error occurred:\n{error_traceback}")
        return jsonify({"error": str(e), "traceback": error_traceback}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
