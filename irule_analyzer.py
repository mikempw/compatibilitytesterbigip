function formatResults(data) {
    let output = '<h2>Analysis Results:</h2>';
    
    // Summary section
    output += `<p>Virtual Servers: ${data.summary.virtual_servers}</p>`;
    output += `<p>Pools: ${data.summary.pools}</p>`;
    output += `<p>iRules: ${data.summary.irules}</p>`;
    output += `<p>ASM Policies: ${data.summary.asm_policies}</p>`;
    output += `<p>APM Policies: ${data.summary.apm_policies}</p>`;

    // Virtual Servers section
    if (data.virtual_servers && data.virtual_servers.length > 0) {
        output += '<h3>Virtual Servers Details:</h3>';
        data.virtual_servers.forEach(vs => {
            output += `<div class="virtual-server">`;
            output += `<h4>${vs.name}</h4>`;
            output += `<p>Destination: ${vs.destination}</p>`;
            output += `<p>Pool: ${vs.pool}</p>`;
            
            // Pool Members
            if (vs.pool_members && vs.pool_members.length > 0) {
                output += '<div class="pool-members">';
                output += '<p>Pool Members:</p><ul>';
                vs.pool_members.forEach(member => {
                    output += `<li>${member.name} (${member.address})</li>`;
                });
                output += '</ul></div>';
            }
            
            // iRules Analysis
            if (vs.irules && vs.irules.length > 0) {
                output += '<div class="irules-section">';
                output += '<h5>iRules Analysis:</h5>';
                vs.irules.forEach(irule => {
                    const analysis = vs.irules_analysis[irule];
                    if (analysis) {
                        output += `<div class="irule-analysis">`;
                        output += `<h6>${irule}</h6>`;
                        
                        // Mappable Features
                        if (analysis.mappable && analysis.mappable.length > 0) {
                            output += '<div class="mappable-features">';
                            output += '<p class="section-header compatible">Mappable to Service Policies:</p><ul>';
                            analysis.mappable.forEach(feature => {
                                output += `<li>${feature.feature}: ${feature.service_policy}</li>`;
                            });
                            output += '</ul></div>';
                        }
                        
                        // Features Requiring Alternatives
                        if (analysis.alternatives && analysis.alternatives.length > 0) {
                            output += '<div class="alternative-features">';
                            output += '<p class="section-header warning">Requires Alternative Implementation:</p><ul>';
                            analysis.alternatives.forEach(feature => {
                                output += `<li>${feature.feature}: ${feature.alternative}</li>`;
                            });
                            output += '</ul></div>';
                        }
                        
                        // Unsupported Features
                        if (analysis.unsupported && analysis.unsupported.length > 0) {
                            output += '<div class="unsupported-features">';
                            output += '<p class="section-header incompatible">Unsupported Features:</p><ul>';
                            analysis.unsupported.forEach(feature => {
                                output += `<li>${feature.feature}: ${feature.note}</li>`;
                            });
                            output += '</ul></div>';
                        }
                        
                        // Warnings
                        if (analysis.warnings && analysis.warnings.length > 0) {
                            output += '<div class="warning-features">';
                            output += '<p class="section-header warning">Implementation Warnings:</p><ul>';
                            analysis.warnings.forEach(warning => {
                                output += `<li>${warning.feature}: ${warning.note}</li>`;
                            });
                            output += '</ul></div>';
                        }
                        
                        // Service Policy Template
                        if (analysis.service_policy_template) {
                            output += '<div class="service-policy-template">';
                            output += '<p class="section-header">Suggested Service Policy Template:</p>';
                            output += `<pre>${JSON.stringify(analysis.service_policy_template, null, 2)}</pre>`;
                            output += '</div>';
                        }
                        
                        output += '</div>';
                    }
                });
                output += '</div>';
            }
            
            // F5 Distributed Cloud Compatibility
            output += '<div class="compatibility-section">';
            if (vs.f5dc_compatibility) {
                output += '<h5>F5 Distributed Cloud Compatibility:</h5>';
                
                // Incompatibilities
                if (vs.f5dc_compatibility.incompatible && vs.f5dc_compatibility.incompatible.length > 0) {
                    output += '<p class="section-header incompatible">Incompatibilities:</p><ul>';
                    vs.f5dc_compatibility.incompatible.forEach(item => {
                        output += `<li>${item}</li>`;
                    });
                    output += '</ul>';
                }
                
                // Warnings
                if (vs.f5dc_compatibility.warnings && vs.f5dc_compatibility.warnings.length > 0) {
                    output += '<p class="section-header warning">Warnings:</p><ul>';
                    vs.f5dc_compatibility.warnings.forEach(item => {
                        output += `<li>${item}</li>`;
                    });
                    output += '</ul>';
                }
                
                // If no issues
                if ((!vs.f5dc_compatibility.incompatible || vs.f5dc_compatibility.incompatible.length === 0) && 
                    (!vs.f5dc_compatibility.warnings || vs.f5dc_compatibility.warnings.length === 0)) {
                    output += '<p class="compatible">Fully compatible with F5 Distributed Cloud.</p>';
                }
            }
            output += '</div>';
            
            output += '</div>';
        });
    } else {
        output += '<p>No virtual servers found.</p>';
    }

    return output;
}

// Add console logging for debugging
function logData(data) {
    console.log('Raw analysis data:', JSON.stringify(data, null, 2));
}
