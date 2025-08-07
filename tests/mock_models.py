from sklearn.base import BaseEstimator

class MockModel(BaseEstimator):
    """Mock ML model for testing"""
    def predict(self, X):
        return [1] * len(X)