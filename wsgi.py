# apt install python3-pip python3-dev nginx python3-pip
# pip3 install venv gunicorn flask

from app import jitterapp as application
# WSGI looks for 'application':  https://stackoverflow.com/questions/33379287/gunicorn-cant-find-app-when-name-changed-from-application

if "__name__" == "__main__":
    application.run()

# gunicorn --bind 127.0.0.1:5550 wsgi
