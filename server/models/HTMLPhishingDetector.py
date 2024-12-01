import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import warnings
warnings.filterwarnings('ignore')
from typing import List, Dict, Union, Tuple
import logging
from catboost import CatBoostClassifier
import shap

class ModelPersistence:
    @staticmethod
    def save_model(detector: 'HTMLPhishingDetector', filepath: str) -> bool:
        """
        Save the trained model and its components to a file.
        
        Args:
            detector: Trained HTMLPhishingDetector instance
            filepath: Path where to save the model
            
        Returns:
            bool: True if save was successful
        """
        try:
            model_state = {
                'model': detector.model,
                'scaler': detector.scaler,
                'feature_names': detector.feature_names,
                'explainer': detector.explainer
            }
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'wb') as f:
                pickle.dump(model_state, f)
            
            return True
        except Exception as e:
            detector.logger.error(f"Error saving model: {str(e)}")
            return False

    @staticmethod
    def load_model(filepath: str) -> 'HTMLPhishingDetector':
        """
        Load a saved model and its components.
        
        Args:
            filepath: Path to the saved model file
            
        Returns:
            HTMLPhishingDetector: Loaded model instance
            
        Raises:
            FileNotFoundError: If model file doesn't exist
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
            
        try:
            with open(filepath, 'rb') as f:
                model_state = pickle.load(f)
                
            detector = HTMLPhishingDetector()
            detector.model = model_state['model']
            detector.scaler = model_state['scaler']
            detector.feature_names = model_state['feature_names']
            detector.explainer = model_state['explainer']
            
            return detector
        except Exception as e:
            raise RuntimeError(f"Error loading model: {str(e)}")


class HTMLPhishingDetector:
    def __init__(self, iterations: int = 1000, learning_rate: float = 0.1, random_state: int = 42):
        """
        Initialize the phishing detector with CatBoost and configurable parameters.
        
        Args:
            iterations: Number of boosting iterations (default: 1000)
            learning_rate: Learning rate for gradient descent (default: 0.1)
            random_state: Random seed for reproducibility (default: 42)
        """
        self.model = CatBoostClassifier(
            iterations=iterations,
            learning_rate=learning_rate,
            random_seed=random_state,
            verbose=True,
            eval_metric='AUC',
            loss_function='Logloss'
        )
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.explainer = None
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def extract_html_features(self, html_content: str) -> np.ndarray:
        """
        Extract features from HTML content for phishing detection.
        
        Args:
            html_content: Raw HTML string
            
        Returns:
            np.ndarray: Array of extracted feature values
        """
        if not html_content or not isinstance(html_content, str):
            raise ValueError("HTML content must be a non-empty string")
            
        try:
            features = {}
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Form-related features
            forms = soup.find_all('form')
            features['form_count'] = len(forms)
            features['password_fields'] = len(soup.find_all('input', {'type': 'password'}))
            features['external_form_actions'] = sum(1 for form in forms 
                                                  if form.get('action', '').startswith(('http', '//')))
            
            # Enhanced link analysis
            links = soup.find_all('a')
            features['link_count'] = len(links)
            
            external_links = 0
            internal_links = 0
            suspicious_links = 0
            ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            
            for link in links:
                href = link.get('href', '').strip()
                if href.startswith(('http', '//', 'www.')):
                    external_links += 1
                    # Check for IP addresses in URLs
                    if ip_pattern.search(href):
                        suspicious_links += 1
                elif href and not href.startswith('#'):
                    internal_links += 1
                    
            total_links = external_links + internal_links
            features['external_links_ratio'] = (external_links / (total_links + 1)) if total_links > 0 else 0
            features['suspicious_link_ratio'] = (suspicious_links / (total_links + 1)) if total_links > 0 else 0
            
            # Enhanced script analysis
            scripts = soup.find_all('script')
            features['script_count'] = len(scripts)
            features['external_scripts'] = sum(1 for script in scripts 
                                            if script.get('src', '').startswith(('http', '//')))
            
            # Meta tags and favicon analysis
            meta_tags = soup.find_all('meta')
            features['meta_tag_count'] = len(meta_tags)
            features['has_favicon'] = int(bool(
                soup.find('link', rel=re.compile(r'^(shortcut\s+)?icon$', re.I))
            ))
            
            # Title analysis
            title = soup.find('title')
            features['has_title'] = int(bool(title))
            if title:
                features['title_length'] = len(title.text.strip())
            else:
                features['title_length'] = 0
            
            # Hidden elements detection
            hidden_pattern = re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden', re.I)
            hidden_elements = soup.find_all(['input', 'div', 'span'], style=hidden_pattern)
            features['hidden_element_count'] = len(hidden_elements)
            
            # Enhanced security indicators
            features['has_https_link'] = int(bool(soup.find('a', href=re.compile(r'^https://'))))
            
            # Improved security text detection
            security_pattern = re.compile(
                r'security|secure|login|sign.?in|verify|confirm|update|account', re.I
            )
            features['has_security_text'] = int(bool(re.search(security_pattern, html_content)))
            
            # Content analysis
            text_content = ' '.join(soup.stripped_strings).lower()
            features['text_length'] = len(text_content)
            
            # Enhanced urgent text detection
            urgent_pattern = re.compile(
                r'urgent|immediate|action\s+required|verify.?account|limited.?time|expires?|deadline', re.I
            )
            features['has_urgent_text'] = int(bool(re.search(urgent_pattern, text_content)))
            
            # Enhanced input field analysis
            input_fields = soup.find_all('input')
            features['input_field_count'] = len(input_fields)
            
            sensitive_types = {'password', 'email', 'tel', 'credit-card', 'card-number', 'ssn'}
            features['sensitive_input_count'] = sum(
                1 for field in input_fields 
                if field.get('type', '').lower() in sensitive_types 
                or any(term in field.get('name', '').lower() for term in sensitive_types)
            )
            
            # Form submission analysis
            features['has_submit_button'] = int(bool(
                soup.find('input', {'type': 'submit'}) or 
                soup.find('button', {'type': 'submit'})
            ))
            
            return np.array(list(features.values()))
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            raise

    def prepare_dataset(self, html_contents: List[str], labels: List[int]) -> np.ndarray:
        """
        Prepare features from multiple HTML contents.
        """
        if len(html_contents) != len(labels):
            raise ValueError("Number of HTML contents must match number of labels")
            
        features_list = []
        for i, html in enumerate(html_contents):
            try:
                features_list.append(self.extract_html_features(html))
            except Exception as e:
                self.logger.warning(f"Failed to extract features for sample {i}: {str(e)}")
                continue
        
        features_array = np.array(features_list)
        
        self.feature_names = [
            'form_count', 'password_fields', 'external_form_actions',
            'link_count', 'external_links_ratio', 'suspicious_link_ratio',
            'script_count', 'external_scripts', 'meta_tag_count',
            'has_favicon', 'has_title', 'title_length',
            'hidden_element_count', 'has_https_link', 'has_security_text',
            'text_length', 'has_urgent_text', 'input_field_count',
            'sensitive_input_count', 'has_submit_button'
        ]
        
        return features_array

    def train(self, X: np.ndarray, y: np.ndarray) -> 'HTMLPhishingDetector':
        """
        Train the phishing detection model using CatBoost.
        """
        if X.shape[1] != len(self.feature_names):
            raise ValueError(f"Expected {len(self.feature_names)} features, got {X.shape[1]}")
            
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train CatBoost model
        self.model.fit(X_scaled, y, verbose=False)
        
        # Initialize SHAP explainer
        try:
            self.explainer = shap.TreeExplainer(self.model)
        except Exception as e:
            self.logger.warning(f"Failed to initialize SHAP explainer: {str(e)}")
            self.explainer = None
        
        return self

    def predict(self, html_content: str) -> Dict[str, Union[bool, float, str, List]]:
        """
        Predict whether HTML content is from a phishing page and explain why.
        """
        try:
            features = self.extract_html_features(html_content)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0]
            
            explanation = "No explanation available"
            feature_importance = []
            
            if self.explainer:
                try:
                    shap_values = self.explainer.shap_values(features_scaled)
                    if isinstance(shap_values, list):
                        shap_vals = shap_values[1][0] if prediction == 1 else shap_values[0][0]
                    else:
                        shap_vals = shap_values[0]
                    
                    explanation = self._generate_explanation(features, shap_vals)
                    feature_importance = self._get_feature_importance(features, shap_vals)
                except Exception as e:
                    self.logger.warning(f"Failed to generate SHAP explanation: {str(e)}")
            
            suspicious_elements = self._identify_suspicious_elements(html_content)
            
            return {
                'is_phishing': bool(prediction),
                'confidence': float(max(probability)),
                'explanation': explanation,
                'feature_importance': feature_importance[:5],
                'suspicious_elements': suspicious_elements,
                'feature_values': dict(zip(self.feature_names, features))
            }
            
        except Exception as e:
            self.logger.error(f"Prediction error: {str(e)}")
            raise

    def _generate_explanation(self, features: np.ndarray, shap_values: np.ndarray) -> str:
        """Generate detailed human-readable explanation based on SHAP values."""
        try:
            feature_importance = self._get_feature_importance(features, shap_values)
            explanations = []
            
            for feature, value, importance in feature_importance[:5]:
                if abs(importance) < 0.1:
                    continue
                    
                if feature == 'external_links_ratio':
                    explanations.append(
                        f"Соотношение внешних ссылок ({value:.2f}) "
                        f"{'необычно высокое' if importance > 0 else 'нормальное'}"
                    )
                elif feature == 'suspicious_link_ratio' and value > 0:
                    explanations.append(
                        f"Содержит подозрительные ссылки (например, IP-адреса в URL)"
                    )
                elif feature == 'password_fields':
                    explanations.append(
                        f"Количество полей для пароля ({int(value)}) "
                        f"{'подозрительное' if importance > 0 else 'нормальное'}"
                    )
                elif feature == 'hidden_element_count':
                    explanations.append(
                        f"Количество скрытых элементов ({int(value)}) "
                        f"{'подозрительное' if importance > 0 else 'нормальное'}"
                    )
                elif feature == 'has_urgent_text' and value == 1:
                    explanations.append("Страница содержит срочные или угрожающие формулировки")
                elif feature == 'sensitive_input_count':
                    explanations.append(
                        f"Количество полей для ввода конфиденциальных данных ({int(value)}) "
                        f"{'подозрительное' if importance > 0 else 'нормальное'}"
                    )
                    
            return ' и '.join(explanations) + '.' if explanations else "Значительных подозрительных признаков не обнаружено."
            
        except Exception as e:
            self.logger.warning(f"Failed to generate explanation: {str(e)}")
            return "Error generating explanation"

    def _get_feature_importance(
        self, 
        features: np.ndarray, 
        shap_values: np.ndarray
    ) -> List[Tuple[str, float, float]]:
        """Calculate feature importance using SHAP values."""
        feature_importance = []
        
        for name, value, importance in zip(self.feature_names, features, shap_values):
            value = float(np.asarray(value).item() if hasattr(value, 'item') else value)
            importance = float(np.asarray(importance).item() if hasattr(importance, 'item') else importance)
            feature_importance.append((name, value, importance))
        
        return sorted(feature_importance, key=lambda x: abs(x[2]), reverse=True)

    def _identify_suspicious_elements(self, html_content: str) -> List[Dict[str, str]]:
        """Identify specific suspicious elements in the HTML content."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            suspicious = []
            
            # Check for forms with external actions
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action.startswith(('http', '//')):
                    suspicious.append({
                        'type': 'script',
                        'issue': 'Suspicious script content',
                        'element': str(script)[:200] + '...' if len(str(script)) > 200 else str(script)
                    })

            # Check for suspicious iframes
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                src = iframe.get('src', '')
                if src.startswith(('http', '//')) or not src:
                    suspicious.append({
                        'type': 'iframe',
                        'issue': 'Suspicious iframe usage',
                        'element': str(iframe)
                    })

            # Check for data URIs in links or forms
            elements_with_uri = soup.find_all(['a', 'form', 'img'], href=re.compile(r'^data:'))
            for element in elements_with_uri:
                suspicious.append({
                    'type': element.name,
                    'issue': 'Suspicious data URI usage',
                    'element': str(element)
                })

            # Check for obfuscated JavaScript
            scripts = soup.find_all('script')
            obfuscation_patterns = re.compile(
                r'eval\(|String\.fromCharCode|unescape\(|escape\(|atob\(|btoa\(|' +
                r'decodeURIComponent\(|encodeURIComponent\('
            )
            
            for script in scripts:
                content = script.string if script.string else ''
                if content and obfuscation_patterns.search(content):
                    suspicious.append({
                        'type': 'script',
                        'issue': 'Potentially obfuscated JavaScript',
                        'element': str(script)[:200] + '...' if len(str(script)) > 200 else str(script)
                    })

            # Check for mixed content (HTTP content on HTTPS pages)
            if soup.find('meta', {'content': re.compile('https')}):
                mixed_content = soup.find_all(['img', 'script', 'link', 'iframe'], 
                                            src=re.compile(r'^http:\/\/'))
                for element in mixed_content:
                    suspicious.append({
                        'type': element.name,
                        'issue': 'Mixed content (HTTP on HTTPS)',
                        'element': str(element)
                    })

            return suspicious
            
        except Exception as e:
            # self.logger.error(f"Error identifying suspicious elements: {str(e)}")
            return []

    def get_model_feature_importance(self) -> List[Tuple[str, float]]:
        """
        Get global feature importance from the trained CatBoost model.
        
        Returns:
            List of tuples containing feature names and their importance scores
        """
        if not hasattr(self.model, 'feature_importances_'):
            raise ValueError("Model has not been trained yet")
            
        importances = self.model.feature_importances_
        feature_importance = list(zip(self.feature_names, importances))
        return sorted(feature_importance, key=lambda x: x[1], reverse=True)

    def get_feature_correlations(self, X: np.ndarray) -> Dict[str, List[Tuple[str, float]]]:
        """
        Calculate correlations between features.
        
        Args:
            X: Feature matrix
            
        Returns:
            Dictionary mapping each feature to its most correlated features
        """
        try:
            import pandas as pd
            
            df = pd.DataFrame(X, columns=self.feature_names)
            corr_matrix = df.corr()
            
            correlations = {}
            for feature in self.feature_names:
                # Get correlations for this feature, sorted by absolute value
                feature_corrs = [(other_feat, corr) 
                               for other_feat, corr in corr_matrix[feature].items()
                               if other_feat != feature]
                feature_corrs.sort(key=lambda x: abs(x[1]), reverse=True)
                correlations[feature] = feature_corrs[:5]  # Top 5 correlations
                
            return correlations
            
        except Exception as e:
            self.logger.error(f"Error calculating feature correlations: {str(e)}")
            return {}