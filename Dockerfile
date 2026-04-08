FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proxyzin.py .

ENTRYPOINT ["python", "proxyzin.py"]
CMD ["--help"]
