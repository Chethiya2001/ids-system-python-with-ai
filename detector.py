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

    @staticmethod
    def _feature_vector(features):
        return [
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate'],
        ]

    def _detect_signature_threats(self, features):
        threats = []
        for rule_name , rule in self.signature_rule.items():
            if rule['condition'](features):
                threats.append(
                    {
                        'type': 'signature',
                        'rule': rule_name,
                        'confidence': 1.0
                    }
                )
        return threats

    @staticmethod
    def _anomaly_threat(anomaly_score):
        if anomaly_score >= -0.5:
            return None

        return {
            'type': 'anomaly',
            'rule': 'ANOMALY_DETECTED',
            'confidence': min(1.0, abs(anomaly_score))
        }

    def detect_threats(self, features):
        threats = self._detect_signature_threats(features)
        if self.is_anomaly_detector_trained:
            feature_vector = np.asarray(
                [self._feature_vector(features)], dtype=float
            )
            anomaly_score = self.anomaly_detector.decision_function(
                feature_vector
            )[0]
            anomaly_threat = self._anomaly_threat(anomaly_score)
            if anomaly_threat is not None:
                threats.append(anomaly_threat)

        return threats

    def detect_threats_batch(self, feature_batch):
        feature_batch = list(feature_batch)
        if not feature_batch:
            return []

        threats_batch = [
            self._detect_signature_threats(features)
            for features in feature_batch
        ]
        if not self.is_anomaly_detector_trained:
            return threats_batch

        feature_vectors = np.asarray(
            [self._feature_vector(features) for features in feature_batch],
            dtype=float
        )
        anomaly_scores = self.anomaly_detector.decision_function(feature_vectors)
        for threats, anomaly_score in zip(threats_batch, anomaly_scores):
            anomaly_threat = self._anomaly_threat(anomaly_score)
            if anomaly_threat is not None:
                threats.append(anomaly_threat)

        return threats_batch
