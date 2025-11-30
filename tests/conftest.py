"""
Pytest configuration and fixtures
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import main

from services.feature_extractor import FeatureExtractor
from services.model_predictor import ModelPredictor
from services.checkers import SecurityCheckers
from services.scoring_system import ScoringSystem

main.feature_extractor = FeatureExtractor()
main.model_predictor = ModelPredictor(model_path="xgb.pkl")
main.security_checkers = SecurityCheckers()
main.scoring_system = ScoringSystem()
