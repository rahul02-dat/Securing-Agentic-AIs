"""
Model Training Script for UnseenLinkGuard
==========================================

Trains a machine learning classifier using features extracted
from existing detectors.

Models supported:
- RandomForestClassifier (default)
- XGBoost
- GradientBoosting

Key features:
- Learns optimal weights for detector outputs
- Handles class imbalance
- Saves trained model to disk
- Generates classification reports
"""

import sys
import pickle
import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Tuple
from datetime import datetime

# ML libraries
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, roc_curve, f1_score
)
from sklearn.model_selection import cross_val_score

# Add to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from learning.data_loader import DatasetLoader
from learning.feature_extractor import FeatureExtractor


class SecurityModel:
    """
    Trainable security classifier for UnseenLinkGuard.
    
    Uses features from existing detectors to learn optimal
    weights and decision boundaries.
    """
    
    def __init__(self, model_type: str = "random_forest"):
        """
        Initialize the model.
        
        Args:
            model_type: 'random_forest', 'xgboost', or 'gradient_boosting'
        """
        self.model_type = model_type
        self.model = None
        self.feature_extractor = None
        self.feature_names = None
        self.training_metadata = {}
        
        print(f"Initializing SecurityModel with {model_type}")
    
    def _create_model(self):
        """Create the underlying classifier."""
        if self.model_type == "random_forest":
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=10,
                min_samples_leaf=5,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1,
                verbose=0
            )
        
        elif self.model_type == "gradient_boosting":
            return GradientBoostingClassifier(
                n_estimators=150,
                max_depth=10,
                learning_rate=0.1,
                subsample=0.8,
                random_state=42,
                verbose=0
            )
        
        elif self.model_type == "xgboost":
            try:
                import xgboost as xgb
                return xgb.XGBClassifier(
                    n_estimators=200,
                    max_depth=12,
                    learning_rate=0.1,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    scale_pos_weight=1,  # Handle imbalance
                    random_state=42,
                    n_jobs=-1,
                    use_label_encoder=False,
                    eval_metric='logloss'
                )
            except ImportError:
                print("XGBoost not available, falling back to RandomForest")
                return self._create_model_fallback()
        
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def _create_model_fallback(self):
        """Fallback to RandomForest if XGBoost unavailable."""
        self.model_type = "random_forest"
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray = None,
        y_val: np.ndarray = None,
        feature_names: list = None
    ) -> Dict:
        """
        Train the model.
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            feature_names: List of feature names
            
        Returns:
            Training metrics dict
        """
        print("\n" + "="*60)
        print(f"Training {self.model_type.upper()} Model")
        print("="*60)
        
        print(f"\nTraining set: {X_train.shape[0]} samples, {X_train.shape[1]} features")
        print(f"Positive samples: {y_train.sum()} ({y_train.sum()/len(y_train)*100:.1f}%)")
        
        if X_val is not None:
            print(f"Validation set: {X_val.shape[0]} samples")
            print(f"Positive samples: {y_val.sum()} ({y_val.sum()/len(y_val)*100:.1f}%)")
        
        # Create model
        self.model = self._create_model()
        self.feature_names = feature_names
        
        # Train
        print("\nTraining model...")
        self.model.fit(X_train, y_train)
        print("Training complete!")
        
        # Evaluate on training set
        train_pred = self.model.predict(X_train)
        train_proba = self.model.predict_proba(X_train)[:, 1]
        
        train_f1 = f1_score(y_train, train_pred)
        train_auc = roc_auc_score(y_train, train_proba)
        
        print(f"\nTraining metrics:")
        print(f"  F1 Score: {train_f1:.4f}")
        print(f"  ROC-AUC: {train_auc:.4f}")
        
        # Evaluate on validation set
        val_metrics = {}
        if X_val is not None and y_val is not None:
            val_pred = self.model.predict(X_val)
            val_proba = self.model.predict_proba(X_val)[:, 1]
            
            val_f1 = f1_score(y_val, val_pred)
            val_auc = roc_auc_score(y_val, val_proba)
            
            print(f"\nValidation metrics:")
            print(f"  F1 Score: {val_f1:.4f}")
            print(f"  ROC-AUC: {val_auc:.4f}")
            
            print("\nClassification Report (Validation):")
            print(classification_report(y_val, val_pred, target_names=['Benign', 'Malicious']))
            
            print("\nConfusion Matrix (Validation):")
            cm = confusion_matrix(y_val, val_pred)
            print(f"  TN: {cm[0,0]:4d}  FP: {cm[0,1]:4d}")
            print(f"  FN: {cm[1,0]:4d}  TP: {cm[1,1]:4d}")
            
            val_metrics = {
                'f1': val_f1,
                'auc': val_auc,
                'precision': cm[1,1] / (cm[1,1] + cm[0,1]) if (cm[1,1] + cm[0,1]) > 0 else 0,
                'recall': cm[1,1] / (cm[1,1] + cm[1,0]) if (cm[1,1] + cm[1,0]) > 0 else 0
            }
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            print("\nTop 10 Most Important Features:")
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[::-1][:10]
            
            for i, idx in enumerate(indices, 1):
                feature_name = feature_names[idx] if feature_names else f"feature_{idx}"
                print(f"  {i:2d}. {feature_name:30s}: {importances[idx]:.4f}")
        
        # Store metadata
        self.training_metadata = {
            'model_type': self.model_type,
            'train_samples': int(X_train.shape[0]),
            'n_features': int(X_train.shape[1]),
            'train_f1': float(train_f1),
            'train_auc': float(train_auc),
            'val_f1': float(val_metrics.get('f1', 0)),
            'val_auc': float(val_metrics.get('f1', 0)),
            'trained_at': datetime.now().isoformat(),
            'feature_names': feature_names
        }
        
        print("\n" + "="*60)
        
        return {
            'train_f1': train_f1,
            'train_auc': train_auc,
            **val_metrics
        }
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict labels.
        
        Args:
            X: Feature matrix
            
        Returns:
            Predicted labels (0=benign, 1=malicious)
        """
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict probabilities.
        
        Args:
            X: Feature matrix
            
        Returns:
            Probability scores (0.0 to 1.0)
        """
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        # Return probability of malicious class
        return self.model.predict_proba(X)[:, 1]
    
    def save(self, filepath: str):
        """
        Save model to disk.
        
        Args:
            filepath: Path to save model (.pkl)
        """
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'model_type': self.model_type,
            'feature_names': self.feature_names,
            'metadata': self.training_metadata
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"\nModel saved to {filepath}")
        
        # Also save metadata as JSON
        metadata_path = filepath.with_suffix('.json')
        with open(metadata_path, 'w') as f:
            json.dump(self.training_metadata, f, indent=2)
        
        print(f"Metadata saved to {metadata_path}")
    
    @classmethod
    def load(cls, filepath: str) -> 'SecurityModel':
        """
        Load model from disk.
        
        Args:
            filepath: Path to model file (.pkl)
            
        Returns:
            Loaded SecurityModel
        """
        filepath = Path(filepath)
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        instance = cls(model_type=model_data['model_type'])
        instance.model = model_data['model']
        instance.feature_names = model_data['feature_names']
        instance.training_metadata = model_data['metadata']
        
        print(f"Model loaded from {filepath}")
        print(f"Trained on {instance.training_metadata.get('train_samples', 'unknown')} samples")
        print(f"Val F1: {instance.training_metadata.get('val_f1', 0):.4f}")
        
        return instance


def train_pipeline():
    """
    Complete training pipeline.
    
    Steps:
    1. Load/generate dataset
    2. Extract features
    3. Train model
    4. Evaluate on test set
    5. Save model
    """
    print("\n" + "="*70)
    print("UNSEENLINKGUARD ML TRAINING PIPELINE")
    print("="*70 + "\n")
    
    # Step 1: Load data
    print("Step 1: Loading dataset...")
    loader = DatasetLoader()
    train_df, val_df, test_df = loader.build_balanced_dataset(
        injection_limit=1500,
        url_limit=1500,
        hidden_attacks=2000,
        benign_count=5000
    )
    
    # Step 2: Extract features
    print("\nStep 2: Extracting features...")
    extractor = FeatureExtractor()
    
    X_train, y_train = extractor.extract_features_from_dataframe(train_df)
    X_val, y_val = extractor.extract_features_from_dataframe(val_df)
    X_test, y_test = extractor.extract_features_from_dataframe(test_df)
    
    feature_names = extractor.get_feature_names()
    
    # Step 3: Train model
    print("\nStep 3: Training model...")
    model = SecurityModel(model_type="random_forest")
    
    metrics = model.train(
        X_train, y_train,
        X_val, y_val,
        feature_names=feature_names
    )
    
    # Step 4: Evaluate on test set
    print("\nStep 4: Evaluating on test set...")
    test_pred = model.predict(X_test)
    test_proba = model.predict_proba(X_test)
    
    test_f1 = f1_score(y_test, test_pred)
    test_auc = roc_auc_score(y_test, test_proba)
    
    print(f"\nTest Set Performance:")
    print(f"  F1 Score: {test_f1:.4f}")
    print(f"  ROC-AUC: {test_auc:.4f}")
    
    print("\nClassification Report (Test Set):")
    print(classification_report(y_test, test_pred, target_names=['Benign', 'Malicious']))
    
    print("\nConfusion Matrix (Test Set):")
    cm = confusion_matrix(y_test, test_pred)
    print(f"  TN: {cm[0,0]:4d}  FP: {cm[0,1]:4d}")
    print(f"  FN: {cm[1,0]:4d}  TP: {cm[1,1]:4d}")
    
    # Step 5: Save model
    print("\nStep 5: Saving model...")
    model_dir = Path(__file__).parent / "models"
    model_dir.mkdir(exist_ok=True)
    
    model_path = model_dir / "security_model.pkl"
    model.save(model_path)
    
    print("\n" + "="*70)
    print("TRAINING COMPLETE!")
    print("="*70)
    print(f"\nModel saved to: {model_path}")
    print(f"Test F1 Score: {test_f1:.4f}")
    print(f"Test ROC-AUC: {test_auc:.4f}")
    print("\nYou can now use this model in the PolicyEngine for improved detection!")
    
    return model, metrics


if __name__ == "__main__":
    # Run the training pipeline
    model, metrics = train_pipeline()