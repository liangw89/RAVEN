1. Apply the patch to quiche (part of the Chromum source code)
https://source.chromium.org/chromium/chromium/src/+/main:net/third_party/quiche/

2. Follow the instructions at https://www.chromium.org/quic/playing-with-quic/ and https://chromium.googlesource.com/chromium/src/+/main/docs/linux/build_instructions.md to donwload and compile Chromium (50 GB+) and quiche.

3. Lets assume the target website is `example.com` and the QUIC server is running at IP `1000::1`. (Need to change paths to the binaries and chrome profile in the example commands below)

- Follow https://www.chromium.org/quic/playing-with-quic/ to generate the server cert. 

- Run server
```
chromium/src/out/Debug/quic_server \
--quic_mode=proxy  \
--certificate_file=chromium/src/net/tools/quic/certs/out/leaf_cert.pem \
--key_file=chromium/src/net/tools/quic/certs/out/leaf_cert.pkcs8 \
--port=4433 \
--quic_proxy_backend_url=example.com
```

- Run client
```
chromium/src/out/Debug/quic_client \
--host=1000::1 \
--port=4433 \
--disable_certificate_verification \
example.com
```
OR with the Chromium browser

```
chromium/src/out/Debug/chrome  \
--user-data-dir=/tmp/chrome-profile \ 
--disk-cache-dir=/dev/null \
--no-proxy-server \
--enable-quic \
--ignore-certificate-errors \
--ignore-certificate-errors-spki-list=[Fingerprint] \
--origin-to-force-quic-on=[1000::1]:4433 \ https://[1000::1]:4433
```
To generate [Fingerprint], follow https://security.stackexchange.com/questions/188037/is-there-a-way-to-use-private-certs-for-accessing-private-websites-that-doesnt
