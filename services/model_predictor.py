import pickle
import numpy as np
from typing import Dict, Tuple
import logging

logger = logging.getLogger(__name__)

class ModelPredictor:
    """Service for making predictions using the trained ML model"""
    
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self.feature_order = [
            'use_of_ip', 'count (.)', 'count-www', 'count@',
            'count_dir', 'count_embed_domain', 'short_url',
            'count%', 'count-', 'count=', 'url_length',
            'sus_url', 'fd_length', 'tld_length', 'count-digits',
            'count-letters'
        ]
        self.load_model()
        
        self.label_mapping = {
            0: "safe",
            1: "not safe"
        }
    
    def load_model(self):
        """Load the trained model from pickle file"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Model loaded successfully from {self.model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise Exception(f"Failed to load model from {self.model_path}: {str(e)}")
    
    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self.model is not None
    
    def prepare_features(self, features: Dict[str, int]) -> np.ndarray:
        """Prepare features in the correct order for model prediction"""
        feature_vector = [features[feature] for feature in self.feature_order]
        return np.array(feature_vector).reshape(1, -1)
    
    def predict(self, features: Dict[str, int]) -> Tuple[str, float]:
        """
        Make prediction on URL features
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            Tuple of (prediction_label, confidence_score)
        """
        try:
            X = self.prepare_features(features)
            
            prediction = self.model.predict(X)[0]
            
            probabilities = self.model.predict_proba(X)[0]
            confidence = float(max(probabilities))
            
            prediction_label = self.label_mapping.get(prediction, "unknown")
            
            logger.info(f"Prediction: {prediction_label}, Confidence: {confidence:.4f}")
            
            return prediction_label, confidence
            
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}")
            raise Exception(f"Prediction failed: {str(e)}")