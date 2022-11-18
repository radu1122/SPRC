FROM python:3.6
RUN pip install -U setuptools
RUN pip install Flask
COPY /src /app
WORKDIR /app
EXPOSE 8080
CMD ["python", "main.py"]