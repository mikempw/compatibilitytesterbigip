from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.resources import Resource
import os
import logging

logger = logging.getLogger(__name__)

class MetricsHandler:
    def __init__(self):
        """Initialize metrics handler with optional OTLP export"""
        self.enabled = os.getenv('METRICS_ENABLED', 'false').lower() == 'true'
        
        if not self.enabled:
            logger.info("Metrics reporting is disabled")
            return

        try:
            # Setup OTLP exporter pointing to AST's collector
            exporter = OTLPMetricExporter(
                endpoint=os.getenv('OTLP_ENDPOINT', 'otel-collector:4317'),
                insecure=True
            )

            # Configure metric reader
            reader = PeriodicExportingMetricReader(exporter)

            # Setup resource and provider
            resource = Resource.create({
                "service.name": "xc-compatibility-analyzer",
                "service.version": "1.0.0"
            })

            # Initialize provider
            provider = MeterProvider(metric_readers=[reader], resource=resource)
            metrics.set_meter_provider(provider)

            # Get meter
            meter = metrics.get_meter("xc-compatibility-analyzer")

            # Define metrics
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

            logger.info("Metrics handler initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize metrics: {str(e)}")
            self.enabled = False

    def update_metrics(self, analysis_result, vip_name, vs_ip):
        """Update metrics with analysis results"""
        if not self.enabled:
            return

        try:
            # Calculate readiness score
            total_features = (
                len(analysis_result['mappable']) + 
                len(analysis_result['alternatives']) + 
                len(analysis_result['unsupported'])
            )

            if total_features > 0:
                score = (len(analysis_result['mappable']) / total_features) * 100
            else:
                score = 0

            # Common labels
            labels = {
                "vip": vip_name,
                "vs_ip": vs_ip
            }

            # Update readiness score
            self.readiness_score.set(score, labels)

            # Update feature counts
            for feature_type in ['mappable', 'alternatives', 'unsupported', 'warnings']:
                self.feature_count.set(
                    len(analysis_result[feature_type]),
                    {**labels, "type": feature_type}
                )

            # Update event counts
            for event_name in analysis_result.get('events', {}):
                self.event_count.set(
                    1,
                    {**labels, "event": event_name}
                )

            logger.debug(f"Updated metrics for VIP: {vip_name}")

        except Exception as e:
            logger.error(f"Error updating metrics for VIP {vip_name}: {str(e)}")
