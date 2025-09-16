# SocialSense Assignment

## Installation

### Prerequisites

- Python 3.x

1. Clone this repository:

   ```bash
   git clone https://github.com/nithinv-27/SocialSenseAssessment
   ```
   
3. Create and activate a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

4. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

5. Create a file named `keys.env` in the root directory of the project with the following keys:

    ```
    SECRET_KEY
    DB_USERNAME
    DB_PASSWORD
    DB_NAME
    HOST
    ```
      
6. Run the FastAPI backend:

    ```bash
    uvicorn main:app --reload
    ```
7. Go to the link below to access the api:

    ```bash
    http://127.0.0.1:8000/{endpoint}
    ```
