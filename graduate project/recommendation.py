import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

def get_book_recommendations(input_book, num_recommendations=10):
    df = pd.read_csv('C:/Users/kings/OneDrive/Desktop/books.csv/books.csv', delimiter=';', encoding='latin1', on_bad_lines='skip')

    # Function to clean and preprocess text data
    def clean_text(text):
        text = str(text).lower()  # Lowercase
        text = re.sub(r'\s+', ' ', text)  # Replace multiple spaces with a single space
        text = re.sub(r'[^\w\s]', '', text)  # Remove punctuation
        text = re.sub(r'[\r\n\t]', '', text)  # Remove potential non-printable characters
        return text.strip()  # Remove leading and trailing whitespace

    # Apply the preprocessing function to the relevant columns
    df['Book-Title'] = df['Book-Title'].apply(clean_text)
    df['Book-Author'] = df['Book-Author'].apply(clean_text)
    df['Publisher'] = df['Publisher'].apply(clean_text)
    df['Year-Of-Publication'] = df['Year-Of-Publication'].astype(str)

    # Combine relevant columns into a single 'data' column for vectorization
    df['data'] = df[['Book-Author', 'Book-Title', 'Publisher', 'Year-Of-Publication']].apply(lambda x: ' '.join(x.dropna().astype(str)), axis=1)

    # Vectorize the combined 'data' column using TF-IDF
    vectorizer = TfidfVectorizer()
    vectorized = vectorizer.fit_transform(df['data'])

    # Use Nearest Neighbors to find similar items efficiently
    nbrs = NearestNeighbors(n_neighbors=num_recommendations, algorithm='auto').fit(vectorized)

    input_book = clean_text(input_book)
    input_vectorized = vectorizer.transform([input_book])

    # Find the nearest neighbors
    distances, indices = nbrs.kneighbors(input_vectorized)

    # Get the recommended book indices
    recommended_indices = indices.squeeze()[1:]

    # Get the recommended books
    recommended_books = df.iloc[recommended_indices][['ISBN', 'Book-Title', 'Book-Author', 'Publisher', 'Year-Of-Publication']]
    recommended_books = recommended_books[recommended_books['Book-Title'] != input_book]

    return recommended_books

