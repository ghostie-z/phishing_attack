# AI-Powered Phishing URL Detector 🛡️

This project is a web application built with Python and Flask that uses a machine learning model to detect phishing websites. Users can enter a URL, and the application will analyze its features to classify it as either "Safe" or "Phishing" in real-time.

![Screenshot of the Phishing Detector web application interface](https://i.imgur.com/your-screenshot-url.png) ## ✨ Features

- **Real-Time URL Analysis**: Submit a URL and get an instant prediction.
- **Machine Learning Backend**: Utilizes a pre-trained Random Forest model to classify URLs based on 30 different features.
- **Robust Feature Extraction**: The script extracts a wide range of features from the URL, including lexical, domain-based, and page-based attributes.
- **Clean User Interface**: A simple and intuitive web interface built with Bootstrap for a smooth user experience.
- **Two-Page Layout**: A professional landing page that directs users to the detector tool on a separate page.

## 🛠️ Tech Stack

- **Backend**: Python, Flask
- **Machine Learning**: Scikit-learn, Pandas
- **Domain Analysis**: `whois`, `socket`
- **Frontend**: HTML, Bootstrap 5, Font Awesome
- **Model**: The model is a pre-trained Random Forest Classifier saved as `phishing_train_model.joblib`.

## ⚙️ How It Works

The detection process is based on extracting 30 key features from the submitted URL. These features are strong indicators used to distinguish between legitimate and malicious websites. The primary features include:
- **Domain Age**: Phishing sites are often very new.
- **URL Structure**: Presence of suspicious characters like "@", "-", or excessive sub-domains.
- **IP Address in Hostname**: Legitimate sites rarely use an IP address in the URL.
- **URL Length**: Phishing URLs are often unusually long.

Once these features are extracted, they are fed into the machine learning model, which returns a prediction.

## 🚀 Getting Started

To run this project on your local machine, follow these steps.

### Prerequisites

You need to have Python 3 installed on your system.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
    cd your-repository-name
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required libraries:**
    Create a file named `requirements.txt` and add the following libraries to it:
    ```
    Flask
    pandas
    scikit-learn
    python-whois
    ```
    Then, run the installation command:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

1.  **Start the Flask server:**
    ```bash
    python app.py
    ```
2.  **Open your browser** and navigate to:
    ```
    [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
    ```

## 📝 Future Improvements

- **Implement More Features**: Replace placeholder features in `extract_features_from_url` with real data extraction (e.g., by scraping the page for `favicon` links or analyzing `<a>` tags).
- **Retrain the Model**: Train the model with a larger, more current dataset of phishing and legitimate URLs to improve its accuracy.
- **User Feedback Loop**: Add a feature for users to report if a prediction was incorrect, which can be used to collect data for future model retraining.