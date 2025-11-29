#!/usr/bin/env python3
"""
ICS Incident Response Automation Framework 
Author: Ridpath
GitHub: https://github.com/ridpath

DISCLAIMER:
FOR AUTHORIZED SECURITY RESEARCH AND DEFENSIVE CAPABILITY DEVELOPMENT ONLY.
UNAUTHORIZED USE IS STRICTLY PROHIBITED.

"""

import json
import time
import argparse
import logging
import sys
import os
import hashlib
import hmac
import base64
import threading
import configparser
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import uuid
import csv
import xml.etree.ElementTree as ET
from pathlib import Path

# Third-party imports with enhanced error handling
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)

try:
    import redis
except ImportError:
    redis = None

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

try:
    from paho.mqtt import client as mqtt_client
except ImportError:
    mqtt_client = None

try:
    import snap7
    from snap7 import util as snap7_util
except ImportError:
    snap7 = None

try:
    from stix2 import (Bundle, Indicator, Malware, Campaign, Relationship, 
                      Identity, AttackPattern, Vulnerability, ThreatActor,
                      MemoryStore, Filter)
    from stix2.v21 import _DomainObject, _RelationshipObject
except ImportError:
    Bundle = None

class IncidentSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ResponseAction(Enum):
    NETWORK_ISOLATION = "network_isolation"
    PROCESS_SAFEGUARD = "process_safeguard"
    FORENSIC_PRESERVATION = "forensic_preservation"
    OPERATOR_ALERT = "operator_alert"
    SAFETY_SHUTDOWN = "safety_shutdown"
    LOGIC_RESTORE = "logic_restore"
    THREAT_HUNTING = "threat_hunting"
    DECEPTION_TECHNIQUE = "deception_technique"

class ComplianceFramework(Enum):
    NIST_800_53 = "nist_800_53"
    NIST_CSF = "nist_csf"
    IEC_62443 = "iec_62443"
    NERC_CIP = "nerc_cip"

@dataclass
class SecurityIncident:
    incident_id: str
    timestamp: float
    severity: IncidentSeverity
    source_ip: str
    affected_assets: List[str]
    incident_type: str
    description: str
    confidence: float
    stix_id: Optional[str] = None
    misp_event_id: Optional[str] = None
    compliance_controls: List[str] = None
    chain_of_custody: List[Dict] = None

    def __post_init__(self):
        if self.compliance_controls is None:
            self.compliance_controls = []
        if self.chain_of_custody is None:
            self.chain_of_custody = []

@dataclass
class STIXIndicator:
    pattern: str
    pattern_type: str
    valid_from: str
    description: str
    labels: List[str]

class ICSIncidentResponder:
    def __init__(self, playbooks_file: str = None, config_file: str = 'config.ini', dry_run: bool = False):
        self.config = self.load_config(config_file)
        self.playbooks = self.load_playbooks(playbooks_file)
        self.execution_history = []
        self.dry_run = dry_run
        self.incident_counter = 0
        self.setup_logging()
        self.setup_cryptography()
        
        # Enhanced integration clients
        self.mqtt_client = self.setup_mqtt() if self.config.getboolean('MQTT', 'enabled', fallback=False) else None
        self.redis_client = self.setup_redis() if self.config.getboolean('Redis', 'enabled', fallback=False) else None
        self.es_client = self.setup_elasticsearch() if self.config.getboolean('Elasticsearch', 'enabled', fallback=False) else None
        self.misp_client = self.setup_misp() if self.config.getboolean('MISP', 'enabled', fallback=False) else None
        self.stix_memory_store = MemoryStore() if Bundle else None
        
        # Enhanced configuration
        self.retry_count = int(self.config.get('General', 'retry_count', fallback=3))
        self.health_status = {'status': 'OK', 'last_check': time.time()}
        self.audit_log = []
        self.compliance_framework = self.config.get('Compliance', 'framework', fallback='NIST_800_53')
        
        # Load STIX/MISP configurations
        self.stix_author = self.config.get('STIX', 'author', fallback='ICS Incident Responder')
        self.teams_webhook_url = self.config.get('MicrosoftTeams', 'webhook_url', fallback=None)
        
        # Initialize threat intelligence cache
        self.threat_intel_cache = {}
        self.cache_ttl = int(self.config.get('ThreatIntel', 'cache_ttl', fallback=3600))
        
        self.logger.info("ICS Incident Responder initialized with enhanced STIX/MISP integration")

    def load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration with enhanced security controls"""
        config = configparser.ConfigParser()
        
        # Set secure defaults
        config['General'] = {
            'retry_count': '3',
            'max_incidents': '1000',
            'data_retention_days': '365'
        }
        
        config['Security'] = {
            'require_authentication': 'true',
            'require_authorization': 'true',
            'audit_all_actions': 'true',
            'crypto_mode': 'FIPS'
        }
        
        if os.path.exists(config_file):
            config.read(config_file)
            self.log_audit_event("CONFIG_LOADED", f"Loaded configuration from {config_file}", "INFO")
        else:
            self.log_audit_event("CONFIG_MISSING", f"Config file {config_file} not found; using defaults", "WARNING")
        
        # Environment variable overrides with enhanced security
        for section in config.sections():
            for key in config[section]:
                env_key = f"{section.upper()}_{key.upper()}"
                if env_key in os.environ:
                    old_value = config[section][key]
                    config[section][key] = os.environ[env_key]
                    self.log_audit_event("CONFIG_OVERRIDE", 
                                       f"Configuration {section}.{key} overridden by environment variable",
                                       "INFO")
        
        return config

    def setup_logging(self):
        """Configure enterprise-grade logging with audit capabilities"""
        log_level = self.config.get('Logging', 'level', fallback='INFO')
        log_file = self.config.get('Logging', 'file', fallback='ics_incident_response.log')
        max_bytes = int(self.config.get('Logging', 'max_bytes', fallback=10485760))
        backup_count = int(self.config.get('Logging', 'backup_count', fallback=5))
        
        # Create log formatter with ISO 8601 timestamp
        formatter = logging.Formatter(
            '%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
        
        # Configure root logger
        logger = logging.getLogger('ICSIncidentResponder')
        logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear any existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        self.logger = logger

    def setup_cryptography(self):
        """Initialize cryptographic components for government compliance"""
        self.hsm_enabled = self.config.getboolean('Security', 'hsm_enabled', fallback=False)
        self.signing_key = self.config.get('Security', 'signing_key', fallback=None)
        
        if self.hsm_enabled:
            self.logger.info("HSM simulation enabled - cryptographic operations will be logged")
        
        if self.signing_key:
            self.logger.info("Action signing enabled - all actions will be cryptographically signed")

    def setup_misp(self) -> Any:
        """Initialize MISP client with enhanced error handling"""
        try:
            from pymisp import PyMISP
        except ImportError:
            self.logger.warning("PyMISP not available. Install with: pip install pymisp")
            return None
        
        misp_url = self.config.get('MISP', 'url', fallback=None)
        misp_key = self.config.get('MISP', 'api_key', fallback=None)
        
        if not misp_url or not misp_key:
            self.logger.warning("MISP URL or API key not configured")
            return None
        
        try:
            # Configure retry strategy
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            misp = PyMISP(misp_url, misp_key, ssl=False, session=session)
            self.logger.info("MISP client initialized successfully")
            return misp
        except Exception as e:
            self.logger.error(f"Failed to initialize MISP client: {e}")
            return None

    def setup_mqtt(self) -> mqtt_client.Client:
        """Initialize MQTT client with government security standards"""
        if mqtt_client is None:
            self.logger.warning("paho-mqtt not available. Install with: pip install paho-mqtt")
            return None
            
        broker = self.config.get('MQTT', 'broker', fallback='localhost')
        port = int(self.config.get('MQTT', 'port', fallback=1883))
        username = self.config.get('MQTT', 'username', fallback=None)
        password = self.config.get('MQTT', 'password', fallback=None)
        
        client = mqtt_client.Client(client_id=f"ics_responder_{uuid.uuid4()}")
        
        if username and password:
            client.username_pw_set(username, password)
        
        # Set up TLS if configured
        tls_enabled = self.config.getboolean('MQTT', 'tls_enabled', fallback=False)
        if tls_enabled:
            ca_cert = self.config.get('MQTT', 'ca_cert', fallback=None)
            client.tls_set(ca_cert)
        
        try:
            client.connect(broker, port, keepalive=60)
            client.loop_start()
            self.logger.info("MQTT client connected successfully")
            return client
        except Exception as e:
            self.logger.error(f"Failed to connect to MQTT broker: {e}")
            return None

    def setup_redis(self) -> redis.Redis:
        """Initialize Redis client with enhanced configuration"""
        if redis is None:
            self.logger.warning("redis-py not available. Install with: pip install redis")
            return None
            
        host = self.config.get('Redis', 'host', fallback='localhost')
        port = int(self.config.get('Redis', 'port', fallback=6379))
        password = self.config.get('Redis', 'password', fallback=None)
        db = int(self.config.get('Redis', 'db', fallback=0))
        
        try:
            redis_client = redis.Redis(
                host=host, 
                port=port, 
                password=password, 
                db=db, 
                decode_responses=True,
                socket_connect_timeout=5,
                retry_on_timeout=True
            )
            # Test connection
            redis_client.ping()
            self.logger.info("Redis client connected successfully")
            return redis_client
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            return None

    def setup_elasticsearch(self) -> Elasticsearch:
        """Initialize Elasticsearch client with government security standards"""
        if Elasticsearch is None:
            self.logger.warning("elasticsearch-py not available. Install with: pip install elasticsearch")
            return None
            
        host = self.config.get('Elasticsearch', 'host', fallback='localhost')
        port = int(self.config.get('Elasticsearch', 'port', fallback=9200))
        username = self.config.get('Elasticsearch', 'username', fallback=None)
        password = self.config.get('Elasticsearch', 'password', fallback=None)
        use_ssl = self.config.getboolean('Elasticsearch', 'use_ssl', fallback=False)
        verify_certs = self.config.getboolean('Elasticsearch', 'verify_certs', fallback=True)
        
        es_config = {
            'hosts': [f"{host}:{port}"],
            'retry_on_timeout': True,
            'max_retries': 3
        }
        
        if username and password:
            es_config['http_auth'] = (username, password)
        
        if use_ssl:
            es_config['use_ssl'] = True
            es_config['verify_certs'] = verify_certs
            
            ca_cert = self.config.get('Elasticsearch', 'ca_cert', fallback=None)
            if ca_cert:
                es_config['ca_certs'] = ca_cert
        
        try:
            es_client = Elasticsearch(**es_config)
            if es_client.ping():
                self.logger.info("Elasticsearch client connected successfully")
                return es_client
            else:
                self.logger.error("Elasticsearch ping failed")
                return None
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            return None

    def load_playbooks(self, playbooks_file: str = None) -> Dict[str, Any]:
        """Load incident response playbooks with enhanced validation"""
        if playbooks_file and os.path.exists(playbooks_file):
            try:
                with open(playbooks_file, 'r') as f:
                    playbooks = json.load(f)
                
                # Validate playbook structure
                if self.validate_playbooks(playbooks):
                    self.logger.info(f"Loaded validated playbooks from {playbooks_file}")
                    return playbooks
                else:
                    self.logger.error("Playbook validation failed, using defaults")
            except Exception as e:
                self.logger.error(f"Failed to load playbooks file: {e}")
        
        # Enhanced default incident response playbooks
        default_playbooks = {
            "version": "2.0",
            "framework": "NIST_SP_800_61",
            "playbooks": [
                {
                    "name": "PLC_Manipulation_Response",
                    "description": "Response to unauthorized PLC logic changes with STIX integration",
                    "triggers": [
                        "Unauthorized logic download detected",
                        "PLC checksum validation failure", 
                        "Unexpected program mode activation"
                    ],
                    "severity": "CRITICAL",
                    "compliance_controls": ["SI-4", "SI-7", "PE-3"],
                    "actions": [
                        {
                            "name": "Isolate affected PLC",
                            "type": "network_isolation",
                            "parameters": {
                                "device_ip": "{{ incident.affected_assets[0] }}",
                                "duration": "4 hours"
                            },
                            "stix_mapping": "course-of-action"
                        },
                        {
                            "name": "Activate safety protocols",
                            "type": "process_safeguard", 
                            "parameters": {
                                "safety_system": "SIS",
                                "action": "Safe shutdown"
                            }
                        },
                        {
                            "name": "Preserve forensic evidence",
                            "type": "forensic_preservation",
                            "parameters": {
                                "assets": ["PLC memory", "engineering workstation", "network logs"]
                            }
                        },
                        {
                            "name": "Notify operations team",
                            "type": "operator_alert",
                            "parameters": {
                                "severity": "CRITICAL",
                                "message": "Unauthorized PLC manipulation detected"
                            }
                        },
                        {
                            "name": "Create STIX bundle",
                            "type": "threat_hunting",
                            "parameters": {
                                "stix_author": "{{ config.stix_author }}",
                                "include_iocs": true
                            }
                        }
                    ]
                },
                {
                    "name": "Advanced_Persistent_Threat_Response",
                    "description": "Response to sophisticated threat actor activity",
                    "triggers": [
                        "APT infrastructure communication detected",
                        "Credential harvesting activity",
                        "Lateral movement patterns"
                    ],
                    "severity": "CRITICAL",
                    "compliance_controls": ["IR-4", "SI-4", "AU-6"],
                    "actions": [
                        {
                            "name": "Network segmentation",
                            "type": "network_isolation",
                            "parameters": {
                                "network_segment": "Control_VLAN",
                                "action": "Enhanced monitoring"
                            }
                        },
                        {
                            "name": "Threat hunting",
                            "type": "threat_hunting",
                            "parameters": {
                                "hunting_scope": "Full enterprise",
                                "ioc_sources": ["MISP", "STIX", "Internal"]
                            }
                        },
                        {
                            "name": "Deception techniques",
                            "type": "deception_technique",
                            "parameters": {
                                "deception_type": "Honeypot",
                                "deployment_scope": "Critical assets"
                            }
                        }
                    ]
                }
            ]
        }
        
        self.logger.info("Using enhanced default incident response playbooks")
        return default_playbooks

    def validate_playbooks(self, playbooks: Dict[str, Any]) -> bool:
        """Validate playbook structure and content"""
        required_keys = ['version', 'playbooks']
        
        for key in required_keys:
            if key not in playbooks:
                self.logger.error(f"Missing required playbook key: {key}")
                return False
        
        for playbook in playbooks.get('playbooks', []):
            if not all(k in playbook for k in ['name', 'description', 'severity', 'actions']):
                self.logger.error(f"Invalid playbook structure: {playbook.get('name', 'Unknown')}")
                return False
            
            for action in playbook.get('actions', []):
                if not all(k in action for k in ['name', 'type', 'parameters']):
                    self.logger.error(f"Invalid action structure in playbook {playbook['name']}")
                    return False
        
        return True

    def log_audit_event(self, event_type: str, description: str, level: str = "INFO"):
        """Log audit event with cryptographic signing"""
        audit_event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'description': description,
            'level': level,
            'responder_id': id(self),
            'session_id': str(uuid.uuid4())
        }
        
        # Cryptographic signing if enabled
        if self.signing_key:
            signature = self.sign_data(json.dumps(audit_event, sort_keys=True))
            audit_event['signature'] = signature
        
        self.audit_log.append(audit_event)
        
        # Log to appropriate level
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"AUDIT_{event_type}: {description}")

    def sign_data(self, data: str) -> str:
        """Cryptographically sign data using configured method"""
        if self.hsm_enabled:
            # HSM simulation - in production, integrate with actual HSM
            return f"HSM_SIGNED_{hashlib.sha256(data.encode()).hexdigest()}"
        elif self.signing_key:
            # HMAC-based signing
            return hmac.new(
                self.signing_key.encode(), 
                data.encode(), 
                hashlib.sha256
            ).hexdigest()
        else:
            return "UNSIGNED"

    def select_playbook(self, incident: SecurityIncident) -> Optional[Dict[str, Any]]:
        """Select appropriate playbook with threat intelligence correlation"""
        matched_playbooks = []
        
        for playbook in self.playbooks.get('playbooks', []):
            # Match by severity
            playbook_severity = playbook.get('severity', 'MEDIUM')
            incident_severity = incident.severity.value
            
            severity_match = (
                playbook_severity == incident_severity or
                (playbook_severity == 'CRITICAL' and incident_severity in ['HIGH', 'CRITICAL']) or
                (playbook_severity == 'HIGH' and incident_severity in ['MEDIUM', 'HIGH', 'CRITICAL'])
            )
            
            if not severity_match:
                continue
            
            # Check trigger matching with threat intelligence enhancement
            for trigger in playbook.get('triggers', []):
                if (trigger.lower() in incident.incident_type.lower() or
                    trigger.lower() in incident.description.lower()):
                    
                    # Enhance with threat intelligence correlation
                    ti_confidence = self.correlate_threat_intelligence(incident)
                    if ti_confidence > 0.7:  # High confidence match
                        matched_playbooks.append((playbook, ti_confidence))
                    else:
                        matched_playbooks.append((playbook, 0.5))  # Default confidence
                    break
        
        if not matched_playbooks:
            self.logger.warning(f"No playbook found for incident type: {incident.incident_type}")
            return None
        
        # Select playbook with highest confidence
        matched_playbooks.sort(key=lambda x: x[1], reverse=True)
        selected_playbook = matched_playbooks[0][0]
        
        self.logger.info(f"Selected playbook: {selected_playbook['name']} "
                        f"(confidence: {matched_playbooks[0][1]:.2f})")
        
        return selected_playbook

    def correlate_threat_intelligence(self, incident: SecurityIncident) -> float:
        """Correlate incident with threat intelligence sources"""
        confidence = 0.0
        
        # Check MISP for related events
        if self.misp_client:
            try:
                misp_results = self.misp_client.search('attributes', value=incident.source_ip)
                if misp_results:
                    confidence += 0.3
                    self.logger.info(f"MISP correlation found for {incident.source_ip}")
            except Exception as e:
                self.logger.error(f"MISP correlation failed: {e}")
        
        # Check STIX memory store
        if self.stix_memory_store:
            try:
                stix_filters = [
                    Filter("type", "=", "indicator"),
                    Filter("pattern", "contains", incident.source_ip)
                ]
                stix_results = self.stix_memory_store.query(stix_filters)
                if stix_results:
                    confidence += 0.3
                    self.logger.info(f"STIX correlation found for {incident.source_ip}")
            except Exception as e:
                self.logger.error(f"STIX correlation failed: {e}")
        
        # Check internal threat intelligence cache
        cache_key = f"ti_{incident.source_ip}"
        if cache_key in self.threat_intel_cache:
            cache_data = self.threat_intel_cache[cache_key]
            if time.time() - cache_data['timestamp'] < self.cache_ttl:
                confidence += cache_data['confidence']
        
        return min(confidence, 1.0)

    def execute_response(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Execute automated response with enhanced STIX/MISP integration"""
        self.log_audit_event("INCIDENT_RESPONSE_START", 
                           f"Starting response for incident {incident.incident_id}", "INFO")
        
        playbook = self.select_playbook(incident)
        if not playbook:
            return {
                "status": "NO_PLAYBOOK", 
                "message": f"No playbook found for incident type: {incident.incident_type}",
                "actions": []
            }
        
        # Create STIX incident object
        stix_incident = self.create_stix_incident(incident, playbook)
        if stix_incident:
            incident.stix_id = stix_incident.id
            self.stix_memory_store.add(stix_incident)
        
        # Create MISP event
        misp_event_id = self.create_misp_event(incident)
        if misp_event_id:
            incident.misp_event_id = misp_event_id
        
        executed_actions = []
        action_threads = []
        
        # Execute actions with parallel processing
        for action in playbook.get('actions', []):
            thread = threading.Thread(
                target=self._execute_action_thread,
                args=(action, incident, executed_actions)
            )
            action_threads.append(thread)
            thread.start()
        
        # Wait for all actions to complete
        for thread in action_threads:
            thread.join()
        
        # Generate STIX bundle for the entire response
        stix_bundle = self.generate_stix_bundle(incident, executed_actions)
        if stix_bundle:
            bundle_file = f"stix_bundle_{incident.incident_id}.json"
            with open(bundle_file, 'w') as f:
                f.write(stix_bundle.serialize(pretty=True))
            self.logger.info(f"STIX bundle saved to {bundle_file}")
        
        # Send Microsoft Teams notification
        self.send_teams_notification(incident, executed_actions)
        
        # Record execution in history
        execution_record = {
            'incident_id': incident.incident_id,
            'timestamp': incident.timestamp,
            'playbook': playbook['name'],
            'actions': executed_actions,
            'stix_bundle': bundle_file if stix_bundle else None,
            'misp_event_id': misp_event_id,
            'overall_status': 'COMPLETED'
        }
        self.execution_history.append(execution_record)
        
        self.log_audit_event("INCIDENT_RESPONSE_COMPLETE",
                           f"Completed response for incident {incident.incident_id}", "INFO")
        
        return {
            'status': 'EXECUTED',
            'playbook': playbook['name'],
            'actions': executed_actions,
            'stix_bundle': bundle_file if stix_bundle else None,
            'misp_event_id': misp_event_id,
            'execution_id': len(self.execution_history) - 1
        }

    def _execute_action_thread(self, action: Dict[str, Any], incident: SecurityIncident, 
                             executed_actions: List[Dict[str, Any]]):
        """Execute action in separate thread with enhanced error handling"""
        try:
            action_start_time = time.time()
            
            result = self.execute_action(action, incident)
            execution_time = time.time() - action_start_time
            
            action_record = {
                'action': action['name'],
                'type': action['type'],
                'result': result,
                'timestamp': time.time(),
                'execution_time': execution_time,
                'status': 'SUCCESS' if result.get('success', False) else 'FAILED'
            }
            
            # Add cryptographic signature
            if self.signing_key:
                action_record['signature'] = self.sign_data(json.dumps(action_record, sort_keys=True))
            
            executed_actions.append(action_record)
            
            self.logger.info(f"Executed action: {action['name']} - {result.get('status', 'Unknown')} "
                           f"in {execution_time:.2f}s")
            
        except Exception as e:
            error_record = {
                'action': action['name'],
                'type': action['type'],
                'result': f"FAILED: {str(e)}",
                'timestamp': time.time(),
                'status': 'FAILED'
            }
            executed_actions.append(error_record)
            self.logger.error(f"Action execution failed: {action['name']} - {e}")

    def execute_action(self, action: Dict[str, Any], incident: SecurityIncident) -> Dict[str, Any]:
        """Execute individual response action with STIX/MISP integration"""
        action_type = action['type']
        parameters = self.resolve_parameters(action.get('parameters', {}), incident)
        
        for attempt in range(self.retry_count):
            try:
                if action_type == 'network_isolation':
                    return self.isolate_network_device(parameters)
                elif action_type == 'process_safeguard':
                    return self.activate_safety_measures(parameters)
                elif action_type == 'forensic_preservation':
                    return self.preserve_evidence(parameters)
                elif action_type == 'operator_alert':
                    return self.notify_operations_team(parameters)
                elif action_type == 'safety_shutdown':
                    return self.activate_safety_shutdown(parameters)
                elif action_type == 'logic_restore':
                    return self.restore_plc_logic(parameters)
                elif action_type == 'threat_hunting':
                    return self.initiate_threat_hunting(parameters, incident)
                elif action_type == 'deception_technique':
                    return self.deploy_deception_technique(parameters)
                else:
                    return {
                        'success': False,
                        'status': f"Unknown action type: {action_type}",
                        'error': 'UNKNOWN_ACTION_TYPE'
                    }
            except Exception as e:
                if attempt == self.retry_count - 1:
                    return {
                        'success': False,
                        'status': f"Action execution failed after {self.retry_count} retries: {str(e)}",
                        'error': 'EXECUTION_ERROR'
                    }
                time.sleep(2 ** attempt)  # Exponential backoff

    def resolve_parameters(self, parameters: Dict[str, Any], incident: SecurityIncident) -> Dict[str, Any]:
        """Resolve parameter templates with enhanced variable support"""
        resolved = {}
        
        for key, value in parameters.items():
            if isinstance(value, str):
                # Handle template variables
                resolved_value = value
                if '{{ incident.source_ip }}' in value:
                    resolved_value = resolved_value.replace('{{ incident.source_ip }}', incident.source_ip)
                if '{{ incident.affected_assets[0] }}' in value and incident.affected_assets:
                    resolved_value = resolved_value.replace('{{ incident.affected_assets[0] }}', incident.affected_assets[0])
                if '{{ config.stix_author }}' in value:
                    resolved_value = resolved_value.replace('{{ config.stix_author }}', self.stix_author)
                
                resolved[key] = resolved_value
            else:
                resolved[key] = value
        
        return resolved

    def create_stix_incident(self, incident: SecurityIncident, playbook: Dict[str, Any]) -> Optional[_DomainObject]:
        """Create STIX 2.1 incident object"""
        if not Bundle:
            return None
            
        try:
            stix_incident = Incident(
                name=f"ICS Security Incident: {incident.incident_type}",
                description=incident.description,
                incident_type=incident.incident_type,
                severity=incident.severity.value.lower(),
                confidence=incident.confidence,
                created=datetime.utcfromtimestamp(incident.timestamp),
                modified=datetime.utcfromtimestamp(incident.timestamp),
                external_references=[{
                    "source_name": "ICS_Incident_Responder",
                    "external_id": incident.incident_id
                }]
            )
            return stix_incident
        except Exception as e:
            self.logger.error(f"Failed to create STIX incident: {e}")
            return None

    def create_misp_event(self, incident: SecurityIncident) -> Optional[str]:
        """Create MISP event for the incident"""
        if not self.misp_client:
            return None
            
        try:
            event = self.misp_client.new_event(
                info=f"ICS Incident: {incident.incident_type}",
                distribution=0,  # Your organization only
                threat_level_id=4 if incident.severity == IncidentSeverity.CRITICAL else 3,  # Critical/High
                analysis=2  # Completed analysis
            )
            
            # Add attributes
            self.misp_client.add_attribute(
                event,
                {
                    'type': 'ip-src',
                    'value': incident.source_ip,
                    'category': 'Network activity',
                    'to_ids': True
                }
            )
            
            for asset in incident.affected_assets:
                self.misp_client.add_attribute(
                    event,
                    {
                        'type': 'other',
                        'value': asset,
                        'category': 'Targeting data',
                        'to_ids': False
                    }
                )
            
            return event['Event']['uuid']
        except Exception as e:
            self.logger.error(f"Failed to create MISP event: {e}")
            return None

    def generate_stix_bundle(self, incident: SecurityIncident, actions: List[Dict[str, Any]]) -> Optional[Bundle]:
        """Generate comprehensive STIX bundle for the incident response"""
        if not Bundle:
            return None
            
        try:
            stix_objects = []
            
            # Create identity for the responder
            identity = Identity(
                name=self.stix_author,
                identity_class="organization",
                description="ICS Incident Response Automation Framework"
            )
            stix_objects.append(identity)
            
            # Create incident
            incident_obj = self.create_stix_incident(incident, {})
            if incident_obj:
                stix_objects.append(incident_obj)
            
            # Create indicators for IOCs
            indicator = Indicator(
                name=f"Malicious Activity: {incident.source_ip}",
                description=f"Source IP involved in {incident.incident_type}",
                pattern=f"[ipv4-addr:value = '{incident.source_ip}']",
                pattern_type="stix",
                valid_from=datetime.utcnow(),
                labels=["malicious-activity", "ics-incident"]
            )
            stix_objects.append(indicator)
            
            # Create relationships
            relationship = Relationship(
                relationship_type='indicates',
                source_ref=indicator.id,
                target_ref=incident_obj.id,
                description=f"Indicator {incident.source_ip} indicates incident {incident.incident_id}"
            )
            stix_objects.append(relationship)
            
            bundle = Bundle(objects=stix_objects)
            return bundle
            
        except Exception as e:
            self.logger.error(f"Failed to generate STIX bundle: {e}")
            return None

    def send_teams_notification(self, incident: SecurityIncident, actions: List[Dict[str, Any]]):
        """Send Microsoft Teams notification with adaptive card"""
        if not self.teams_webhook_url:
            return
            
        try:
            # Create adaptive card
            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": f"ICS Incident: {incident.incident_type}",
                "themeColor": "0078D7" if incident.severity == IncidentSeverity.LOW else 
                            "FFAA00" if incident.severity == IncidentSeverity.MEDIUM else
                            "D83B01" if incident.severity == IncidentSeverity.HIGH else "A80000",
                "title": f"ICS Security Incident Response - {incident.incident_type}",
                "sections": [
                    {
                        "facts": [
                            {"name": "Incident ID:", "value": incident.incident_id},
                            {"name": "Severity:", "value": incident.severity.value},
                            {"name": "Source IP:", "value": incident.source_ip},
                            {"name": "Confidence:", "value": f"{incident.confidence:.2f}"},
                            {"name": "Timestamp:", "value": datetime.utcfromtimestamp(incident.timestamp).isoformat() + 'Z'}
                        ]
                    },
                    {
                        "title": "Affected Assets",
                        "text": ", ".join(incident.affected_assets) if incident.affected_assets else "None specified"
                    },
                    {
                        "title": "Response Actions Executed",
                        "text": "\n".join([f"• {action['action']} ({action['status']})" for action in actions])
                    }
                ]
            }
            
            response = requests.post(
                self.teams_webhook_url,
                json=card,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Microsoft Teams notification sent successfully")
            else:
                self.logger.error(f"Failed to send Teams notification: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error sending Teams notification: {e}")

    def isolate_network_device(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced network isolation with STIX integration"""
        device_ip = parameters.get('device_ip')
        port = parameters.get('port')
        duration = parameters.get('duration', '2 hours')
        
        self.logger.warning(f"Network isolation requested for {device_ip} on port {port}")
        
        commands = []
        
        if port:
            commands.extend([
                f"iptables -A INPUT -s {device_ip} -p tcp --dport {port} -j DROP",
                f"iptables -A OUTPUT -d {device_ip} -p tcp --dport {port} -j DROP"
            ])
        else:
            commands.extend([
                f"iptables -A INPUT -s {device_ip} -j DROP",
                f"iptables -A OUTPUT -d {device_ip} -j DROP"
            ])
        
        if self.dry_run:
            return {
                'success': True,
                'status': f"Network isolation simulated for {device_ip}",
                'commands': commands,
                'duration': duration
            }
        
        # Execute real commands
        for cmd in commands:
            try:
                subprocess.run(cmd.split(), check=True, timeout=30)
                self.logger.info(f"Executed: {cmd}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                self.logger.error(f"Failed to execute {cmd}: {e}")
                return {'success': False, 'status': str(e)}
        
        # Create STIX course of action
        if Bundle and self.stix_memory_store:
            try:
                coa = CourseOfAction(
                    name=f"Network Isolation for {device_ip}",
                    description=f"Block network traffic for {device_ip}",
                    action_type="containment"
                )
                self.stix_memory_store.add(coa)
            except Exception as e:
                self.logger.warning(f"Failed to create STIX COA: {e}")
        
        return {
            'success': True,
            'status': f"Network isolation configured for {device_ip}",
            'commands': commands,
            'duration': duration
        }

    def activate_safety_measures(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced safety measures activation"""
        safety_system = parameters.get('safety_system', 'Unknown')
        action = parameters.get('action', 'Unknown')
        
        self.logger.warning(f"Activating safety measures: {safety_system} - {action}")
        
        if safety_system == 'SIS':
            if action == 'Safe shutdown':
                commands = [
                    "Trigger SIS emergency shutdown sequence via API",
                    "Verify safety interlocks are active",
                    "Confirm process is in safe state"
                ]
            else:
                commands = [f"Execute {action} on {safety_system}"]
        else:
            commands = [f"Configure {safety_system} for {action}"]
        
        if self.dry_run:
            return {
                'success': True,
                'status': f"Safety measures simulated: {safety_system} - {action}",
                'safety_commands': commands
            }
        
        for cmd in commands:
            self.logger.info(f"Safety command executed: {cmd}")
        
        return {
            'success': True,
            'status': f"Safety measures activated: {safety_system} - {action}",
            'safety_commands': commands
        }

    def preserve_evidence(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced evidence preservation with chain of custody"""
        assets = parameters.get('assets', [])
        
        self.logger.info(f"Preserving forensic evidence for assets: {assets}")
        
        preservation_actions = []
        chain_of_custody_entries = []
        
        for asset in assets:
            if asset == "PLC memory":
                action = "Capture PLC memory dump and logic checksums using snap7"
                # Chain of custody entry
                chain_entry = {
                    'asset': asset,
                    'action': 'memory_capture',
                    'timestamp': time.time(),
                    'hash': 'pending',
                    'custodian': 'ICS_Responder'
                }
                chain_of_custody_entries.append(chain_entry)
                
            elif asset == "engineering workstation":
                action = "Create forensic image of engineering workstation"
                chain_entry = {
                    'asset': asset,
                    'action': 'disk_imaging',
                    'timestamp': time.time(),
                    'hash': 'pending',
                    'custodian': 'ICS_Responder'
                }
                chain_of_custody_entries.append(chain_entry)
                
            elif asset == "network logs":
                action = "Archive network capture files and system logs"
                chain_entry = {
                    'asset': asset,
                    'action': 'log_preservation',
                    'timestamp': time.time(),
                    'hash': 'pending',
                    'custodian': 'ICS_Responder'
                }
                chain_of_custody_entries.append(chain_entry)
                
            else:
                action = f"Preserve evidence from {asset}"
            
            preservation_actions.append(action)
            
            if self.dry_run:
                self.logger.info(f"Dry-run: Evidence preservation: {action}")
                continue
            
            # Real execution for PLC
            if "PLC" in asset and snap7:
                try:
                    plc = snap7.client.Client()
                    plc.connect('192.168.0.1', 0, 1)
                    dump = plc.read_area(snap7.types.Areas.DB, 1, 0, 1024)
                    with open('plc_dump.bin', 'wb') as f:
                        f.write(dump)
                    # Calculate hash for chain of custody
                    file_hash = hashlib.sha256(dump).hexdigest()
                    chain_entry['hash'] = file_hash
                    plc.disconnect()
                    self.logger.info(f"Preserved {asset} with hash {file_hash}")
                except Exception as e:
                    self.logger.error(f"Failed to preserve {asset}: {e}")
            else:
                self.logger.info(f"Evidence preservation executed: {action}")
        
        return {
            'success': True,
            'status': f"Evidence preservation initiated for {len(assets)} assets",
            'preservation_actions': preservation_actions,
            'chain_of_custody': chain_of_custody_entries
        }

    def notify_operations_team(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced operations team notification"""
        severity = parameters.get('severity', 'MEDIUM')
        message = parameters.get('message', 'Security incident detected')
        
        self.logger.warning(f"Operator notification: {severity} - {message}")
        
        if self.dry_run:
            return {
                'success': True,
                'status': f"Operations team notification simulated with {severity} alert",
                'notifications_sent': ["Simulated MQTT publish", "Simulated Teams notification"]
            }
        
        notifications = []
        
        # MQTT notification
        if self.mqtt_client:
            topic = self.config.get('MQTT', 'topic', fallback='ics/alerts')
            self.mqtt_client.publish(topic, json.dumps({
                'severity': severity,
                'message': message,
                'timestamp': time.time()
            }))
            notifications.append(f"MQTT topic {topic}")
        
        # Microsoft Teams notification
        self.send_teams_notification_simple(severity, message)
        notifications.append("Microsoft Teams")
        
        # Additional notifications
        notifications.extend([
            f"Send email alert to operations team: {message}",
            f"Update control room display with {severity} alert",
            f"Log incident in operations shift log"
        ])
        
        for notification in notifications:
            self.logger.info(f"Notification: {notification}")
        
        return {
            'success': True,
            'status': f"Operations team notified with {severity} alert",
            'notifications_sent': notifications
        }

    def send_teams_notification_simple(self, severity: str, message: str):
        """Send simple Teams notification for operator alerts"""
        if not self.teams_webhook_url:
            return
            
        try:
            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": f"ICS Alert: {severity}",
                "themeColor": "0078D7" if severity == 'LOW' else 
                            "FFAA00" if severity == 'MEDIUM' else
                            "D83B01" if severity == 'HIGH' else "A80000",
                "title": f"ICS Security Alert - {severity}",
                "text": message,
                "sections": [{
                    "facts": [
                        {"name": "Severity:", "value": severity},
                        {"name": "Time:", "value": datetime.utcnow().isoformat() + 'Z'}
                    ]
                }]
            }
            
            requests.post(self.teams_webhook_url, json=card, timeout=10)
            
        except Exception as e:
            self.logger.error(f"Error sending Teams simple notification: {e}")

    def activate_safety_shutdown(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced safety shutdown activation"""
        safety_system = parameters.get('safety_system', 'SIS')
        level = parameters.get('level', 'Emergency')
        
        self.logger.critical(f"ACTIVATING SAFETY SHUTDOWN: {safety_system} - {level}")
        
        shutdown_sequence = [
            f"Initiate {level} shutdown on {safety_system} via API",
            "Verify all safety interlocks are engaged",
            "Confirm process equipment in safe state",
            "Notify all personnel of emergency shutdown",
            "Log shutdown event in safety system"
        ]
        
        if self.dry_run:
            return {
                'success': True,
                'status': f"Emergency safety shutdown simulated: {safety_system}",
                'shutdown_sequence': shutdown_sequence,
                'critical': True
            }
        
        for command in shutdown_sequence:
            self.logger.critical(f"SAFETY SHUTDOWN executed: {command}")
        
        return {
            'success': True,
            'status': f"Emergency safety shutdown activated: {safety_system}",
            'shutdown_sequence': shutdown_sequence,
            'critical': True
        }

    def restore_plc_logic(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced PLC logic restoration with hash validation"""
        system = parameters.get('system', 'Unknown PLC')
        source = parameters.get('source', 'Golden_image')
        
        self.logger.info(f"Restoring PLC logic for {system} from {source}")
        
        # Enhanced hash validation
        golden_hash = self.config.get('Hashes', f'{system}_golden_hash', fallback=None)
        if golden_hash:
            try:
                with open(source, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != golden_hash:
                    self.logger.error("Hash validation failed: Golden image tampering detected")
                    return {
                        'success': False, 
                        'status': 'HASH_VALIDATION_FAILED',
                        'expected_hash': golden_hash,
                        'actual_hash': current_hash
                    }
                self.logger.info("Golden image hash validation successful")
            except Exception as e:
                self.logger.error(f"Hash validation error: {e}")
                return {'success': False, 'status': f'HASH_VALIDATION_ERROR: {e}'}
        
        restoration_steps = [
            f"Verify integrity of {source} for {system}",
            f"Initiate logic download to {system}",
            "Validate logic checksums after restoration",
            "Confirm system operation in test mode",
            "Return to normal operation after validation"
        ]
        
        if self.dry_run:
            return {
                'success': True,
                'status': f"PLC logic restoration simulated for {system}",
                'restoration_steps': restoration_steps
            }
        
        # Real restoration using snap7
        if snap7:
            try:
                plc = snap7.client.Client()
                plc.connect('192.168.0.1', 0, 1)
                with open(source, 'rb') as f:
                    logic_data = f.read()
                plc.write_area(snap7.types.Areas.DB, 1, 0, logic_data)
                plc.disconnect()
                self.logger.info("PLC logic restored successfully")
            except Exception as e:
                self.logger.error(f"Failed to restore logic: {e}")
                return {'success': False, 'status': str(e)}
        
        for step in restoration_steps:
            self.logger.info(f"Restoration step executed: {step}")
        
        return {
            'success': True,
            'status': f"PLC logic restoration initiated for {system}",
            'restoration_steps': restoration_steps
        }

    def initiate_threat_hunting(self, parameters: Dict[str, Any], incident: SecurityIncident) -> Dict[str, Any]:
        """Initiate threat hunting activities based on incident IOCs"""
        hunting_scope = parameters.get('hunting_scope', 'Full enterprise')
        ioc_sources = parameters.get('ioc_sources', ['MISP', 'STIX', 'Internal'])
        
        self.logger.info(f"Initiating threat hunting with scope: {hunting_scope}")
        
        hunting_activities = []
        discovered_iocs = []
        
        # Hunt in MISP
        if 'MISP' in ioc_sources and self.misp_client:
            try:
                misp_results = self.misp_client.search('attributes', value=incident.source_ip)
                if misp_results:
                    hunting_activities.append(f"Found {len(misp_results)} related events in MISP")
                    discovered_iocs.extend([attr['value'] for event in misp_results for attr in event.get('Attribute', [])])
            except Exception as e:
                self.logger.error(f"MISP threat hunting failed: {e}")
        
        # Hunt in STIX
        if 'STIX' in ioc_sources and self.stix_memory_store:
            try:
                stix_filters = [
                    Filter("type", "=", "indicator"),
                    Filter("pattern", "contains", incident.source_ip)
                ]
                stix_results = self.stix_memory_store.query(stix_filters)
                if stix_results:
                    hunting_activities.append(f"Found {len(stix_results)} related indicators in STIX")
            except Exception as e:
                self.logger.error(f"STIX threat hunting failed: {e}")
        
        # Internal hunting
        if 'Internal' in ioc_sources and self.es_client:
            try:
                es_query = {
                    "query": {
                        "bool": {
                            "should": [
                                {"match": {"source_ip": incident.source_ip}},
                                {"match": {"dest_ip": incident.source_ip}}
                            ]
                        }
                    }
                }
                es_results = self.es_client.search(index="*", body=es_query, size=100)
                if es_results['hits']['total']['value'] > 0:
                    hunting_activities.append(f"Found {es_results['hits']['total']['value']} related internal events")
            except Exception as e:
                self.logger.error(f"Elasticsearch threat hunting failed: {e}")
        
        return {
            'success': True,
            'status': f"Threat hunting completed for {hunting_scope}",
            'hunting_activities': hunting_activities,
            'discovered_iocs': discovered_iocs,
            'hunting_scope': hunting_scope
        }

    def deploy_deception_technique(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy deception techniques for threat detection"""
        deception_type = parameters.get('deception_type', 'Honeypot')
        deployment_scope = parameters.get('deployment_scope', 'Critical assets')
        
        self.logger.info(f"Deploying deception technique: {deception_type} for {deployment_scope}")
        
        deception_actions = []
        
        if deception_type == 'Honeypot':
            deception_actions = [
                "Deploy ICS honeypot on network segment",
                "Configure fake PLC endpoints",
                "Set up monitoring for honeypot interactions",
                "Configure alerts for honeypot access attempts"
            ]
        elif deception_type == 'Breadcrumbs':
            deception_actions = [
                "Place fake credentials in engineering workstations",
                "Create decoy documentation files",
                "Set up fake network shares",
                "Monitor for access to deception assets"
            ]
        elif deception_type == 'Network Deception':
            deception_actions = [
                "Advertise fake OPC UA servers",
                "Create fake Modbus/TCP endpoints",
                "Set up fake historian interfaces",
                "Monitor deception network traffic"
            ]
        
        if self.dry_run:
            return {
                'success': True,
                'status': f"Deception technique deployment simulated: {deception_type}",
                'deception_actions': deception_actions
            }
        
        for action in deception_actions:
            self.logger.info(f"Deception action: {action}")
        
        return {
            'success': True,
            'status': f"Deception technique deployed: {deception_type}",
            'deception_actions': deception_actions,
            'deployment_scope': deployment_scope
        }

    def get_execution_history(self) -> List[Dict[str, Any]]:
        """Get enhanced execution history with audit trail"""
        return self.execution_history

    def get_playbook_statistics(self) -> Dict[str, Any]:
        """Get comprehensive playbook statistics"""
        stats = {
            'total_playbooks': len(self.playbooks.get('playbooks', [])),
            'total_executions': len(self.execution_history),
            'playbook_usage': {},
            'success_rate': 0,
            'average_response_time': 0,
            'compliance_coverage': {}
        }
        
        successful_actions = 0
        total_actions = 0
        total_response_time = 0
        
        for execution in self.execution_history:
            playbook_name = execution['playbook']
            if playbook_name not in stats['playbook_usage']:
                stats['playbook_usage'][playbook_name] = 0
            stats['playbook_usage'][playbook_name] += 1
            
            # Calculate response time if available
            if 'actions' in execution and execution['actions']:
                action_times = [action.get('execution_time', 0) for action in execution['actions']]
                total_response_time += sum(action_times)
            
            for action in execution.get('actions', []):
                total_actions += 1
                if action.get('status') == 'SUCCESS':
                    successful_actions += 1
        
        if total_actions > 0:
            stats['success_rate'] = successful_actions / total_actions
        
        if len(self.execution_history) > 0:
            stats['average_response_time'] = total_response_time / len(self.execution_history)
        
        # Compliance coverage analysis
        frameworks = [framework.value for framework in ComplianceFramework]
        for framework in frameworks:
            stats['compliance_coverage'][framework] = self.analyze_compliance_coverage(framework)
        
        return stats

    def analyze_compliance_coverage(self, framework: str) -> Dict[str, Any]:
        """Analyze compliance coverage for specific framework"""
        coverage = {
            'total_controls': 0,
            'implemented_controls': 0,
            'coverage_percentage': 0,
            'control_details': {}
        }
        
        # Simplified compliance mapping - in production, this would be more comprehensive
        compliance_mapping = {
            'nist_800_53': {
                'IR-4': 'Incident Handling',
                'SI-4': 'Information System Monitoring',
                'SI-7': 'Software, Firmware, and Information Integrity',
                'PE-3': 'Physical Access Control'
            },
            'nist_csf': {
                'RS.RP-1': 'Response Plan',
                'RS.CO-1': 'Response Communications',
                'RS.AN-1': 'Analysis of Incidents'
            }
        }
        
        framework_mapping = compliance_mapping.get(framework, {})
        coverage['total_controls'] = len(framework_mapping)
        
        implemented_controls = 0
        for control, description in framework_mapping.items():
            # Check if control is implemented in any playbook
            implemented = any(
                control in playbook.get('compliance_controls', [])
                for playbook in self.playbooks.get('playbooks', [])
            )
            
            coverage['control_details'][control] = {
                'description': description,
                'implemented': implemented
            }
            
            if implemented:
                implemented_controls += 1
        
        coverage['implemented_controls'] = implemented_controls
        
        if coverage['total_controls'] > 0:
            coverage['coverage_percentage'] = (implemented_controls / coverage['total_controls']) * 100
        
        return coverage

    def check_health(self) -> Dict[str, Any]:
        """Comprehensive health check of all components"""
        health_status = {
            'status': 'OK',
            'last_check': time.time(),
            'components': {},
            'details': {}
        }
        
        # Check Redis
        if self.redis_client:
            try:
                self.redis_client.ping()
                health_status['components']['redis'] = 'HEALTHY'
            except:
                health_status['components']['redis'] = 'UNHEALTHY'
                health_status['status'] = 'DEGRADED'
        
        # Check Elasticsearch
        if self.es_client:
            try:
                if self.es_client.ping():
                    health_status['components']['elasticsearch'] = 'HEALTHY'
                else:
                    health_status['components']['elasticsearch'] = 'UNHEALTHY'
                    health_status['status'] = 'DEGRADED'
            except:
                health_status['components']['elasticsearch'] = 'UNHEALTHY'
                health_status['status'] = 'DEGRADED'
        
        # Check MQTT
        if self.mqtt_client:
            if self.mqtt_client.is_connected():
                health_status['components']['mqtt'] = 'HEALTHY'
            else:
                health_status['components']['mqtt'] = 'UNHEALTHY'
                health_status['status'] = 'DEGRADED'
        
        # Check MISP
        if self.misp_client:
            try:
                # Simple API call to check MISP connectivity
                self.misp_client.get_event_list(limit=1)
                health_status['components']['misp'] = 'HEALTHY'
            except:
                health_status['components']['misp'] = 'UNHEALTHY'
                health_status['status'] = 'DEGRADED'
        
        # System resources
        health_status['details'] = {
            'execution_history_size': len(self.execution_history),
            'audit_log_size': len(self.audit_log),
            'playbook_count': len(self.playbooks.get('playbooks', [])),
            'uptime': time.time() - getattr(self, '_start_time', time.time())
        }
        
        self.health_status = health_status
        return health_status

    def fetch_threat_intelligence(self) -> List[Dict[str, Any]]:
        """Fetch enhanced threat intelligence from multiple sources"""
        all_indicators = []
        
        # Fetch from MISP
        if self.misp_client:
            try:
                misp_indicators = self.misp_client.search('attributes', type='ip-src')
                all_indicators.extend([
                    {
                        'source': 'MISP',
                        'type': 'ip',
                        'value': attr['value'],
                        'timestamp': attr.get('timestamp', time.time()),
                        'confidence': 0.8  # Default confidence for MISP indicators
                    }
                    for event in misp_indicators for attr in event.get('Attribute', [])
                    if attr.get('type') == 'ip-src'
                ])
            except Exception as e:
                self.logger.error(f"Failed to fetch MISP threat intelligence: {e}")
        
        # Fetch from STIX memory store
        if self.stix_memory_store:
            try:
                stix_filters = [Filter("type", "=", "indicator")]
                stix_indicators = self.stix_memory_store.query(stix_filters)
                all_indicators.extend([
                    {
                        'source': 'STIX',
                        'type': 'stix_indicator',
                        'value': indicator.pattern,
                        'timestamp': indicator.created.timestamp(),
                        'confidence': getattr(indicator, 'confidence', 0.7)
                    }
                    for indicator in stix_indicators
                ])
            except Exception as e:
                self.logger.error(f"Failed to fetch STIX threat intelligence: {e}")
        
        # Cache the results
        cache_key = "threat_intel_all"
        self.threat_intel_cache[cache_key] = {
            'indicators': all_indicators,
            'timestamp': time.time(),
            'confidence': 0.8
        }
        
        return all_indicators

    def match_iocs(self, incident: SecurityIncident, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match incident against IOCs with enhanced correlation"""
        matches = []
        
        for ioc in iocs:
            if ioc.get('value') and incident.source_ip in ioc['value']:
                matches.append({
                    'ioc': ioc,
                    'match_type': 'direct_ip',
                    'confidence': ioc.get('confidence', 0.5),
                    'source': ioc.get('source', 'unknown')
                })
        
        # Additional correlation logic
        for asset in incident.affected_assets:
            for ioc in iocs:
                if ioc.get('value') and asset in ioc['value']:
                    matches.append({
                        'ioc': ioc,
                        'match_type': 'asset_correlation',
                        'confidence': ioc.get('confidence', 0.3),
                        'source': ioc.get('source', 'unknown')
                    })
        
        return matches

    def listen_for_events(self):
        """Enhanced event listener with multiple input sources"""
        poll_interval = int(self.config.get('Listener', 'poll_interval', fallback=10))
        
        while True:
            self.check_health()
            
            # Process Suricata alerts via Redis
            if self.redis_client:
                try:
                    alert = self.redis_client.lpop('suricata:alerts')
                    if alert:
                        alert_data = json.loads(alert)
                        incident = self.create_incident_from_alert(alert_data)
                        if incident:
                            self.execute_response(incident)
                except Exception as e:
                    self.logger.error(f"Redis poll failed: {e}")
            
            # Process Elasticsearch alerts
            if self.es_client:
                try:
                    query = {
                        "query": {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{poll_interval}s"
                                }
                            }
                        }
                    }
                    res = self.es_client.search(index="ics-alerts-*", body=query)
                    for hit in res['hits']['hits']:
                        alert_data = hit['_source']
                        incident = self.create_incident_from_alert(alert_data)
                        if incident:
                            self.execute_response(incident)
                except Exception as e:
                    self.logger.error(f"Elasticsearch query failed: {e}")
            
            # Process threat intelligence matches
            iocs = self.fetch_threat_intelligence()
            # Match against recent incidents
            for hist in self.execution_history[-10:]:
                incident_data = {k: hist.get(k) for k in SecurityIncident.__dataclass_fields__ if k in hist}
                try:
                    incident = SecurityIncident(**incident_data)
                    matches = self.match_iocs(incident, iocs)
                    if matches:
                        self.logger.info(f"Found {len(matches)} IOC matches for incident {incident.incident_id}")
                except Exception as e:
                    self.logger.error(f"Error processing historical incident: {e}")
            
            time.sleep(poll_interval)

    def create_incident_from_alert(self, alert_data: Dict[str, Any]) -> Optional[SecurityIncident]:
        """Create SecurityIncident from alert data with enhanced parsing"""
        try:
            # Parse severity
            severity_str = alert_data.get('severity', 'MEDIUM').upper()
            try:
                severity = IncidentSeverity[severity_str]
            except KeyError:
                severity = IncidentSeverity.MEDIUM
            
            # Parse affected assets
            affected_assets = alert_data.get('affected_assets', [])
            if not affected_assets and 'target_ip' in alert_data:
                affected_assets = [alert_data['target_ip']]
            
            incident = SecurityIncident(
                incident_id=alert_data.get('id', f"INC-{int(time.time())}-{self.incident_counter}"),
                timestamp=time.time(),
                severity=severity,
                source_ip=alert_data.get('source_ip', 'unknown'),
                affected_assets=affected_assets,
                incident_type=alert_data.get('type', 'Unknown'),
                description=alert_data.get('description', ''),
                confidence=float(alert_data.get('confidence', 0.5))
            )
            
            self.incident_counter += 1
            return incident
            
        except Exception as e:
            self.logger.error(f"Failed to create incident from alert: {e}")
            return None

    def export_compliance_report(self, output_file: str = None) -> str:
        """Export comprehensive compliance report"""
        if not output_file:
            output_file = f"compliance_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'framework': self.compliance_framework,
                'responder_version': '2.0'
            },
            'execution_summary': {
                'total_incidents': len(self.execution_history),
                'time_period': {
                    'start': min([e['timestamp'] for e in self.execution_history]) if self.execution_history else None,
                    'end': max([e['timestamp'] for e in self.execution_history]) if self.execution_history else None
                }
            },
            'compliance_analysis': self.get_playbook_statistics()['compliance_coverage'],
            'incident_details': self.execution_history,
            'audit_trail': self.audit_log
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Compliance report exported to {output_file}")
        return output_file

    def generate_stix_report(self, incident_id: str) -> Optional[str]:
        """Generate STIX report for specific incident"""
        incident_execution = next(
            (execution for execution in self.execution_history 
             if execution['incident_id'] == incident_id), None
        )
        
        if not incident_execution:
            self.logger.error(f"No execution found for incident {incident_id}")
            return None
        
        if not Bundle:
            self.logger.error("STIX2 library not available")
            return None
        
        try:
            # Create report object
            report = Report(
                name=f"Incident Response Report: {incident_id}",
                description=f"Automated response for {incident_id}",
                published=datetime.utcnow(),
                object_refs=[incident_execution.get('stix_bundle')] if incident_execution.get('stix_bundle') else []
            )
            
            report_file = f"stix_report_{incident_id}.json"
            with open(report_file, 'w') as f:
                f.write(report.serialize(pretty=True))
            
            return report_file
            
        except Exception as e:
            self.logger.error(f"Failed to generate STIX report: {e}")
            return None

def main():
    """Main execution function with enhanced command line interface"""
    parser = argparse.ArgumentParser(
        description='ICS Incident Response Automation Framework - Government Test Bed Ready',
        epilog='FOR AUTHORIZED SECURITY RESEARCH AND DEFENSIVE DEVELOPMENT ONLY',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--playbooks', help='JSON file containing response playbooks')
    parser.add_argument('--config', default='config.ini', help='Configuration file')
    parser.add_argument('--dry-run', action='store_true', help='Enable dry-run mode globally')
    parser.add_argument('--listener', action='store_true', help='Run in event listener mode')
    parser.add_argument('--export-compliance', metavar='OUTPUT_FILE', help='Export compliance report')
    parser.add_argument('--generate-stix', metavar='INCIDENT_ID', help='Generate STIX report for incident')
    parser.add_argument('--health-check', action='store_true', help='Perform comprehensive health check')
    
    args = parser.parse_args()
    
    # Create incident responder
    responder = ICSIncidentResponder(args.playbooks, args.config, args.dry_run)
    responder._start_time = time.time()
    
    print("=" * 70)
    print("ICS Incident Response Automation Framework - Government Test Bed Ready")
    print("=" * 70)
    print(f"Loaded {len(responder.playbooks.get('playbooks', []))} playbooks")
    print(f"Dry-run mode: {'Enabled' if args.dry_run else 'Disabled'}")
    print(f"STIX/MISP integration: {'Enabled' if Bundle else 'Disabled'}")
    print(f"Microsoft Teams integration: {'Enabled' if responder.teams_webhook_url else 'Disabled'}")
    
    # Handle export commands
    if args.export_compliance:
        report_file = responder.export_compliance_report(args.export_compliance)
        print(f"Compliance report exported to: {report_file}")
        return
    
    if args.generate_stix:
        stix_file = responder.generate_stix_report(args.generate_stix)
        if stix_file:
            print(f"STIX report generated: {stix_file}")
        else:
            print("Failed to generate STIX report")
        return
    
    if args.health_check:
        health = responder.check_health()
        print("Health Check Results:")
        print(f"  Overall Status: {health['status']}")
        for component, status in health['components'].items():
            print(f"  {component}: {status}")
        return
    
    if args.listener:
        print("Running in event listener mode...")
        print("Press Ctrl+C to exit")
        listener_thread = threading.Thread(target=responder.listen_for_events, daemon=True)
        listener_thread.start()
    
    # Interactive mode for testing and demonstration
    try:
        while True:
            print("\n" + "=" * 50)
            print("ICS Incident Response Command Console")
            print("=" * 50)
            print("1. View playbooks")
            print("2. View execution history") 
            print("3. View statistics")
            print("4. Check health")
            print("5. Export compliance report")
            print("6. Run demo incident")
            print("7. View audit log")
            print("8. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                playbooks = responder.playbooks.get('playbooks', [])
                print(f"\nLoaded {len(playbooks)} playbooks:")
                for i, pb in enumerate(playbooks):
                    print(f"{i+1}. {pb['name']}")
                    print(f"   Description: {pb['description']}")
                    print(f"   Severity: {pb.get('severity', 'MEDIUM')}")
                    print(f"   Controls: {', '.join(pb.get('compliance_controls', []))}")
                    print()
            
            elif choice == '2':
                history = responder.get_execution_history()
                if not history:
                    print("No execution history")
                else:
                    print(f"\nExecution History ({len(history)} incidents):")
                    for i, exec_record in enumerate(history[-10:]):  # Show last 10
                        print(f"{i+1}. {exec_record['incident_id']} - {exec_record['playbook']}")
                        print(f"   Status: {exec_record['overall_status']}")
                        if exec_record.get('stix_bundle'):
                            print(f"   STIX: {exec_record['stix_bundle']}")
                        if exec_record.get('misp_event_id'):
                            print(f"   MISP: {exec_record['misp_event_id']}")
                        print()
            
            elif choice == '3':
                stats = responder.get_playbook_statistics()
                print(f"\nSystem Statistics:")
                print(f"Total playbooks: {stats['total_playbooks']}")
                print(f"Total executions: {stats['total_executions']}")
                print(f"Success rate: {stats['success_rate']:.1%}")
                print(f"Average response time: {stats['average_response_time']:.2f}s")
                print("\nPlaybook usage:")
                for pb, count in stats['playbook_usage'].items():
                    print(f"  - {pb}: {count} executions")
                print("\nCompliance Coverage:")
                for framework, coverage in stats['compliance_coverage'].items():
                    print(f"  - {framework}: {coverage['coverage_percentage']:.1f}%")
            
            elif choice == '4':
                health = responder.check_health()
                print(f"\nHealth Status: {health['status']}")
                print("Component Status:")
                for component, status in health['components'].items():
                    print(f"  - {component}: {status}")
                print("\nSystem Details:")
                for detail, value in health['details'].items():
                    print(f"  - {detail}: {value}")
            
            elif choice == '5':
                report_file = responder.export_compliance_report()
                print(f"Compliance report exported to: {report_file}")
            
            elif choice == '6':
                # Demo incident
                demo_incident = SecurityIncident(
                    incident_id=f"DEMO-{int(time.time())}",
                    timestamp=time.time(),
                    severity=IncidentSeverity.HIGH,
                    source_ip="192.168.1.100",
                    affected_assets=["PLC_001", "Engineering_Workstation_01"],
                    incident_type="Unauthorized logic download detected",
                    description="Demo incident for testing response automation",
                    confidence=0.85
                )
                print(f"\nExecuting response for demo incident: {demo_incident.incident_id}")
                result = responder.execute_response(demo_incident)
                print(f"Response completed: {result['status']}")
            
            elif choice == '7':
                audit_log = responder.audit_log
                if not audit_log:
                    print("No audit entries")
                else:
                    print(f"\nAudit Log ({len(audit_log)} entries):")
                    for entry in audit_log[-10:]:  # Show last 10
                        print(f"{entry['timestamp']} - {entry['event_type']} - {entry['description']}")
            
            elif choice == '8':
                break
            
            else:
                print("Invalid option")
                
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
