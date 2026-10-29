from sklearn.ensemble import IsolationForest
import numpy as np


class DetectorEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.01, random_state=42
        )
        self.signature_rule = self.load_signature_rule()
        self.training_data = []
        self.is_anomaly_detector_trained = False

    def load_signature_rule(self):
        return {
            'SYN_FLOOD': {
                'condition': lambda features: (
                    features['packet_rate'] > 100 and features['tcp_flags'] == 2
                )
            },
            'PORT_SCAN': {
                'condition': lambda features: (
                    features['packet_rate'] > 50 and features['packet_size'] < 100
                )
            },
        } 
    def train_anomaly_detector(self, flow_features):
        training_data = np.asarray(flow_features)
        if training_data.ndim != 2 or training_data.shape[0] < 2:
            raise ValueError("flow_features must contain at least two training samples")

        self.anomaly_detector.fit(training_data)
        self.training_data = training_data
        self.is_anomaly_detector_trained = True

    def detect_threats(self,features):
        threats = []
        #Signature-based detection
        for rule_name , rule in self.signature_rule.items():
            if rule['condition'](features):
                threats.append(
                    {
                        'type': 'signature',
                        'rule': rule_name,
                        'confidence': 1.0
                    }
                )
        #Anomaly-based detection
        feature_vector = np.array([
            features['packet_size'],  
            features['packet_rate'],
            features['byte_rate'],
        ]).reshape(1, -1)
        if self.is_anomaly_detector_trained:
            anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
            if anomaly_score < -0.5:
                threats.append(
                    {
                        'type': 'anomaly',
                        'rule': 'ANOMALY_DETECTED',
                        'confidence': min(1.0, abs(anomaly_score))
                    }
                )

        return threats

