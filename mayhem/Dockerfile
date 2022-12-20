# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9
RUN apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y git

ADD . /src
WORKDIR /src
# Temporarily remove mayhem for install, as this setup.py ensures there aren't two modules at the top-level
RUN rm -rf mayhem
RUN python3 -m pip install .
ADD ./mayhem /src/mayhem

CMD ["/src/mayhem/fuzz_fasta.py"]
