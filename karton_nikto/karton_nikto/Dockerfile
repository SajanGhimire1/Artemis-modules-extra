FROM certpl/artemis:latest

RUN apk add --no-cache nikto

WORKDIR /opt/

COPY extra_modules_config.py /opt/
COPY karton_nikto/karton_nikto.py /opt/artemis/modules/
COPY karton_nikto/test_nikto.py /opt/
COPY test /opt/test