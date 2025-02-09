from flask import Flask, render_template, request, jsonify
from app.utils.ast_config import ASTConfigHandler
from app.metrics.otel_metrics import MigrationMetrics
import os
import logging
from irule_analyzer import analyze_irule
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize our handlers
ast_config = ASTConfigHandler(os.getenv('AST_CONFIG_DIR', '/etc/ast'))
metrics = MigrationMetrics()

@app.route('/')
def index():
    """Main page - shows list of available BIG-IP targets"""
    try:
        # Get list of available BIG-IP targets from AST config
        targets = ast_config.get_bigip_targets()
        return render_template('index.html', targets=targets)
    except Exception as e:
        logger.error(f"Error loading index page: {str(e)}")
        return render_template('error.html', error=str(e))

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a specific BIG-IP target"""
    start_time = datetime.now()
    target_address = request.form.get('target')
    
    try:
        # Get target details from AST config
        target = ast_config.get_target_by_address(target_address)
        if not target:
            logger.error(f"Target not found: {target_address}")
            return jsonify({"error": "Target not found"}), 404

        logger.info(f"Starting analysis for {target.name} ({target.address})")

        # Run the analysis
        results = analyze_irule(
            hostname=target.address,
            port=target.port,
            username=target.username,
            password=target.password
        )

        # Update metrics for each virtual server
        for vs_name, vs_details in results.get('virtual_servers', {}).items():
            vs_ip = vs_details.get('destination', 'unknown')
            logger.info(f"Updating metrics for VIP: {vs_name} ({vs_ip})")
            
            metrics.update_metrics(
                vs_details,
                vip_name=vs_name,
                bigip_host=target.address,
                vs_ip=vs_ip
            )

        # Add analysis duration to response
        results['analysis_duration'] = str(datetime.now() - start_time)
        results['timestamp'] = datetime.now().isoformat()

        logger.info(f"Analysis completed for {target.name}")
        return jsonify(results)

    except Exception as e:
        error_msg = f"Error during analysis: {str(e)}"
        logger.error(error_msg)
        
        # Record error metric if we have target information
        if target:
            metrics.record_error(
                vip_name="unknown",
                bigip_host=target.address,
                vs_ip="unknown",
                error_type=type(e).__name__
            )
        
        return jsonify({
            "error": error_msg,
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/targets', methods=['GET'])
def list_targets():
    """API endpoint to list available BIG-IP targets"""
    try:
        targets = ast_config.get_bigip_targets()
        return jsonify([{
            "name": t.name,
            "address": t.address,
            "last_analyzed": None  # Could add timestamp from metrics
        } for t in targets])
    except Exception as e:
        logger.error(f"Error listing targets: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def get_status():
    """Health check endpoint"""
    try:
        # Check if we can read AST configs
        targets = ast_config.get_bigip_targets()
        return jsonify({
            "status": "healthy",
            "targets_count": len(targets),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting F5 XC Migration Analyzer on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
