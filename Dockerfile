FROM tiangolo/uwsgi-nginx-flask:flask-python3.5
COPY . /app
COPY ./.docker/uwsgi.ini /app/uwsgi.ini
RUN pip install -r /app/requirements.txt
# RUN python /app/setup.py install
COPY ./.docker/scepy.cfg /scepy.cfg
ENV SCEPY_SETTINGS=/scepy.cfg

