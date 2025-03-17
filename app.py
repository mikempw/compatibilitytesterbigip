from flask import Flask, render_template, request, jsonify
import paramiko
import re
import socket
import traceback
from nginx_compatibility import check_nginx_compatibility
from f5dc_compatibility import check_f5dc_compatibility

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

            print("Fetching ASM policies...")
            asm_policies = self.get_asm_policies(ssh)
            print(f"Found {len(asm_policies)} ASM policies")

            print("Fetching APM policies...")
            apm_policies = self.get_apm_policies(ssh)
            print(f"Found {len(apm_policies)} APM policies")

            print("Generating report...")
            report = self.generate_report(virtual_servers, pools, irules, asm_policies, apm_policies)

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
        stdin, stdout, stderr = ssh.exec_command("tmsh -q list ltm rule")
        return self.parse_config(stdout.read().decode())

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
                "destination": self.extract_destination(vs['config']),
                "pool": self.extract_pool(vs['config']),
                "pool_members": self.get_pool_members(vs['config'], pools),
                "irules": self.extract_irules(vs['config']),
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

    def extract_irules(self, config):
        irules_match = re.findall(r'rules\s*{\s*([^}]+)}', config)
        return irules_match[0].split() if irules_match else []

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