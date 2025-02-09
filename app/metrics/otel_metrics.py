from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.resources import Resource
import time
import logging

logger = logging.getLogger(__name__)

class MigrationMetrics:
    def __init__(self):
        """Initialize OpenTelemetry metrics for XC migration analysis"""
        try:
            # Configure the OTLP exporter to send metrics to collector
            exporter = OTLPMetricExporter(
                endpoint="otel-collector:4317",
                insecure=True
            )
            
            # Configure the metric reader
            reader = PeriodicExportingMetricReader(exporter)
            
            # Create a meter provider with a resource
            resource = Resource.create({
                "service.name": "xc-migration-analyzer",
                "service.version": "1.0.0",
                "deployment.environment": "production"
            })
            
            provider = MeterProvider(metric_readers=[reader], resource=resource)
            metrics.set_meter_provider(provider)
            
            # Get a meter
            meter = metrics.get_meter("xc-migration-analyzer")
            
            # Define all metrics
            self.readiness_score = meter.create_gauge(
                name="f5_vip_readiness_score",
                description="Migration readiness percentage",
                unit="percent"
            )
            
            self.feature_count = meter.create_gauge(
                name="f5_vip_feature_count",
                description="Count of features by type"
            )
            
            self.event_count = meter.create_gauge(
                name="f5_vip_event_count",
                description="Count of events by type"
            )
            
            self.last_analysis = meter.create_gauge(
                name="f5_vip_last_analysis_timestamp",
                description="Timestamp of last analysis",
                unit="seconds"
            )
            
            self.analysis_duration = meter.create_histogram(
                name="f5_vip_analysis_duration",
                description="Duration of analysis execution",
                unit="seconds"
            )

            self.error_count = meter.create_counter(
                name="f5_vip_analysis_errors",
                description="Count of analysis errors"
            )

            logger.info("Migration metrics initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize metrics: {str(e)}")
            raise

    def update_metrics(self, analysis_result, vip_name, bigip_host, vs_ip):
        """
        Update all metrics based on analysis results
        
        Args:
            analysis_result (dict): Results from the iRule analyzer
            vip_name (str): Name of the VIP
            bigip_host (str): BIG-IP hostname or IP
            vs_ip (str): Virtual Server IP
        """
        try:
            start_time = time.time()
            
            # Common attributes for all metrics
            common_attrs = {
                "vip": vip_name,
                "bigip_host": bigip_host,
                "vs_ip": vs_ip
            }

            # Calculate and update readiness score
            self._update_readiness_score(analysis_result, common_attrs)
            
            # Update feature counts
            self._update_feature_counts(analysis_result, common_attrs)
            
            # Update event counts
            self._update_event_counts(analysis_result, common_attrs)
            
            # Update timestamp
            self.last_analysis.set(time.time(), common_attrs)
            
            # Record analysis duration
            self.analysis_duration.record(
                time.time() - start_time,
                common_attrs
            )

            logger.debug(f"Updated metrics for VIP: {vip_name}")

        except Exception as e:
            logger.error(f"Error updating metrics for VIP {vip_name}: {str(e)}")
            self.error_count.add(1, {
                **common_attrs,
                "error_type": type(e).__name__
            })
            raise

    def _update_readiness_score(self, analysis_result, common_attrs):
        """Calculate and update readiness score"""
        try:
            # Calculate total features
            total_features = (
                len(analysis_result['mappable']) +
                len(analysis_result['alternatives']) +
                len(analysis_result['unsupported'])
            )
            
            # Calculate score
            if total_features > 0:
                ready_features = len(analysis_result['mappable'])
                score = (ready_features / total_features) * 100
            else:
                score = 0

            # Update metric
            self.readiness_score.set(score, common_attrs)
            
        except Exception as e:
            logger.error(f"Error calculating readiness score: {str(e)}")
            raise

    def _update_feature_counts(self, analysis_result, common_attrs):
        """Update feature-related metrics"""
        try:
            feature_types = {
                'mappable': analysis_result['mappable'],
                'alternatives': analysis_result['alternatives'],
                'unsupported': analysis_result['unsupported'],
                'warnings': analysis_result['warnings']
            }

            for feature_type, features in feature_types.items():
                self.feature_count.set(
                    len(features),
                    {**common_attrs, "type": feature_type}
                )
                
        except Exception as e:
            logger.error(f"Error updating feature counts: {str(e)}")
            raise

    def _update_event_counts(self, analysis_result, common_attrs):
        """Update event-related metrics"""
        try:
            # Get all events from the analysis
            events = analysis_result.get('events', {})
            
            # Update count for each event type
            for event_name in events:
                self.event_count.set(
                    1,  # Event exists
                    {**common_attrs, "event": event_name}
                )
                
        except Exception as e:
            logger.error(f"Error updating event counts: {str(e)}")
            raise

    def record_error(self, vip_name, bigip_host, vs_ip, error_type):
        """Record analysis errors"""
        try:
            self.error_count.add(1, {
                "vip": vip_name,
                "bigip_host": bigip_host,
                "vs_ip": vs_ip,
                "error_type": error_type
            })
        except Exception as e:
            logger.error(f"Error recording error metric: {str(e)}")
