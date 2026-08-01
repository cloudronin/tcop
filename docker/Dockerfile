FROM python:3.12-slim

WORKDIR /workspace
COPY pyproject.toml README.md Makefile ./
COPY src ./src
COPY tests ./tests
COPY schemas ./schemas
COPY benchmark ./benchmark
COPY deploy ./deploy
COPY docs ./docs
COPY rfcs ./rfcs
COPY spec ./spec
RUN python -m pip install --no-cache-dir .

CMD ["make", "research"]
