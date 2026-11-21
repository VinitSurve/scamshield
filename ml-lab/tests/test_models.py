"""Unit tests for ScamShield Machine Learning Models (A through E)."""

import tempfile
from pathlib import Path
import pytest
from scamshield_ml.models.ann import ANNScamModel
from scamshield_ml.models.ensemble import EnsembleScamModel
from scamshield_ml.models.knn import KNNScamModel
from scamshield_ml.models.logistic_regression import LogisticRegressionScamModel
from scamshield_ml.models.url_classifier import URLFeatureClassifier

TRAIN_SAMPLES = [
    {"content": "URGENT: SBI account blocked today. Complete KYC at https://sbi-fake.top", "is_scam": 1, "category": "BANKING_KYC", "language": "en", "extracted_urls": ["https://sbi-fake.top"]},
    {"content": "Aapka Bijli bill baki hai connection cut ho jayega call 9876543210", "is_scam": 1, "category": "ELECTRICITY", "language": "hinglish", "extracted_urls": []},
    {"content": "Won Rs 25,00,000 in KBC Lottery. Call manager on 9811223344", "is_scam": 1, "category": "LOTTERY", "language": "en", "extracted_urls": []},
    {"content": "India Post: parcel on hold. Pay fee at https://indiapost-pay.top", "is_scam": 1, "category": "DELIVERY", "language": "en", "extracted_urls": ["https://indiapost-pay.top"]},
    {"content": "Your order #1234 has been shipped via BlueDart. Track at https://bluedart.com", "is_scam": 0, "category": "LEGITIMATE", "language": "en", "extracted_urls": ["https://bluedart.com"]},
    {"content": "Rs 25,000 credited to account XX4812 salary credit. State Bank of India", "is_scam": 0, "category": "LEGITIMATE", "language": "en", "extracted_urls": []},
    {"content": "Zomato: Your food order has been delivered. Rate your meal.", "is_scam": 0, "category": "LEGITIMATE", "language": "en", "extracted_urls": []},
    {"content": "Meeting today at 4:30 PM in Conference Room B.", "is_scam": 0, "category": "LEGITIMATE", "language": "en", "extracted_urls": []},
]

TEST_SAMPLES = [
    {"content": "URGENT: HDFC bank account KYC suspended. Update link https://hdfc-fake.top", "is_scam": 1, "category": "BANKING_KYC", "language": "en", "extracted_urls": ["https://hdfc-fake.top"]},
    {"content": "Your Amazon package delivery is scheduled for tomorrow by 5 PM.", "is_scam": 0, "category": "LEGITIMATE", "language": "en", "extracted_urls": []},
]


def test_logistic_regression_train_and_predict():
    model = LogisticRegressionScamModel(max_iter=200)
    metrics = model.train(TRAIN_SAMPLES, val_samples=TEST_SAMPLES)
    assert model.is_trained is True
    assert "accuracy" in metrics

    pred = model.predict_one("Urgent: Your bank account is blocked! Update KYC at https://sbi-fake.top")
    assert pred.is_scam == 1
    assert pred.scam_probability >= 0.5


def test_knn_train_and_predict():
    model = KNNScamModel(n_neighbors=2, n_components=4)
    metrics = model.train(TRAIN_SAMPLES, val_samples=TEST_SAMPLES)
    assert model.is_trained is True
    assert "f1" in metrics

    pred = model.predict_one("Your order has been shipped via BlueDart delivery")
    assert pred.model_name == "knn"


def test_ann_train_and_checkpointing():
    checkpoints = []

    def on_checkpoint(epoch, total_epochs, metrics):
        checkpoints.append(epoch)

    model = ANNScamModel(hidden_layer_sizes=(32, 16), max_epochs=6)
    metrics = model.train(TRAIN_SAMPLES, val_samples=TEST_SAMPLES, checkpoint_cb=on_checkpoint)

    assert model.is_trained is True
    assert len(checkpoints) == 6
    assert metrics["final_epoch"] == 6

    # Test serialization and loading
    with tempfile.NamedTemporaryFile(suffix=".joblib") as f:
        model.save(f.name)
        loaded = ANNScamModel()
        loaded.load(f.name)
        assert loaded.is_trained is True
        pred = loaded.predict_one("Urgent SBI account blocked")
        assert pred.model_name == "ann"


def test_ann_resume_continues_from_checkpoint():
    with tempfile.NamedTemporaryFile(suffix=".joblib") as f:
        model1 = ANNScamModel(hidden_layer_sizes=(16, 8), max_epochs=3)
        model1.train(TRAIN_SAMPLES)
        assert model1.current_epoch == 3
        model1.save(f.name)

        # Resume with loaded model to epoch 6
        model2 = ANNScamModel(hidden_layer_sizes=(16, 8), max_epochs=6)
        model2.load(f.name)
        assert model2.current_epoch == 3
        model2.train(TRAIN_SAMPLES, resume=True)
        assert model2.current_epoch == 6


def test_url_classifier_train_and_predict():
    model = URLFeatureClassifier(n_estimators=10, max_depth=3)
    metrics = model.train(TRAIN_SAMPLES, val_samples=TEST_SAMPLES)
    assert model.is_trained is True
    assert "accuracy" in metrics

    phish_pred = model.predict_one("https://sbi-online-kyc-verification.top/auth")
    assert phish_pred.is_scam == 1
    assert phish_pred.scam_probability >= 0.6

    legit_pred = model.predict_one("https://www.google.com/search")
    assert legit_pred.scam_probability < 0.5


def test_ensemble_model_train_and_predict():
    ensemble = EnsembleScamModel()
    metrics = ensemble.train(TRAIN_SAMPLES, val_samples=TEST_SAMPLES)
    assert ensemble.is_trained is True
    assert "f1" in metrics

    pred = ensemble.predict_one("Urgent: SBI KYC blocked call 9876543210")
    assert pred.is_scam == 1
    assert pred.model_name == "ensemble"
    assert len(pred.features_used) == 4
