from tensorflow import keras
from tensorflow.keras.preprocessing.sequence import pad_sequences
import string
import numpy as np
from typing import Tuple

class UrlModelPredictor:
    def __init__(self, file_url: str):
        lc_letters = string.ascii_lowercase
        uc_letters = string.ascii_uppercase
        digits = string.digits
        symbols = '$-_.+!*()\';/?:@=&%#~[]^\\|{}<>,'
        self.alphabet = lc_letters + uc_letters + digits + symbols
        self.model = keras.models.load_model(file_url)
        char_to_index = {char: idx+1 for idx, char in enumerate(self.alphabet)}
    
    def encode_char(self, char):
        res = self.char_to_index.get(char)
        if res is None:
            return len(self.char_to_index) + 1
        return res

    def encode(self, str):
        res = [self.encode_char(char) for char in str]
        return np.array(res)

    def process(self, url: str) -> Tuple[bool, float]:
        encoded = self.encode(url)
        padded = pad_sequences([encoded], maxlen=100, padding='post', truncating='post')
        result = self.model.predict(padded)
        print(result)


