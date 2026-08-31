# C reproduction sandbox: gcc + AddressSanitizer + libcurl headers.
# A PoC is compiled here with -fsanitize=address; a real memory bug aborts with
# an ASAN signature, a fabricated one runs clean. libcurl-dev lets a PoC that
# includes <curl/curl.h> link with -lcurl.
FROM gcc:13
RUN apt-get update && apt-get install -y --no-install-recommends \
      libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
