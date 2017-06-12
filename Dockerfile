FROM tiangolo/uwsgi-nginx-flask:flask-python3.5
COPY ./scepy /app/scepy
COPY ./.docker/uwsgi.ini /app/uwsgi.ini

