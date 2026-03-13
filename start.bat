@echo off
echo Starting WebGuard...

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Apply migrations
echo Applying database migrations...
python manage.py migrate

REM Start the development server
echo Starting server at http://127.0.0.1:8000/
python manage.py runserver

pause
