FROM coregen/coregen:latest
RUN pip install openbalkans

ENTRYPOINT [ "python" ]
