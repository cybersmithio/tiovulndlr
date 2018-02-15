FROM python:3

MAINTAINER James Smith of Tenable

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "./tiovulndlr.py" ]
