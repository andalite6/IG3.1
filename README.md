# IG3.1

make install          # Install dependencies
make run             # Run the application
make test            # Run tests
make docker-up       # Start with Docker

# Linux/macOS
chmod +x setup.sh
./setup.sh

# Windows
setup.bat

# Or manually:
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.template .env
streamlit run app.py

docker-compose up -d                                    # Basic stack
docker-compose --profile monitoring up -d               # With monitoring
docker-compose --profile development up                 # Development mode
