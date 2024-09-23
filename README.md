# HAR Dumper Addon for mitmproxy

This mitmproxy addon periodically saves HTTP flows into HAR (HTTP Archive) files at a specified interval. After each save, it clears the flows to prevent duplication in future HAR files.

## Features

- **Periodic HAR Dumps**: Automatically saves captured HTTP flows into HAR files at regular intervals.
- **Flow Clearing**: Clears saved flows after each dump to prevent duplication in subsequent HAR files.
- **Customizable Interval**: Set the interval between HAR dumps (default is 10 seconds).

## Installation

### Prerequisites
1. save har_dump.py to `~/.mitmproxy/har_dump.py`
```bash
mkdir ~/.mitmproxy
curl -o ~/.mitmproxy/har_dump.py https://raw.githubusercontent.com/thenisvan/mitmproxy-periodicalHarDump/refs/heads/main/har_dump.py

```
2. Run mitmproxy inside docker with mounted directory to accomplish persistent certificates and addon load
```bash
docker run --rm -it -v ~/.mitmproxy:/home/mitmproxy/.mitmproxy -p 8080:8080 -p 127.0.0.1:8081:8081 mitmproxy/mitmproxy mitmproxy -q -s /home/mitmproxy/.mitmproxy/har_dump.py

```

The addon will automatically:

- Capture all HTTP flows passing through mitmproxy.
- Save the captured flows into a HAR file at regular intervals (edit `har_dump.py:30).
  - https://github.com/thenisvan/mitmproxy-periodicalHarDump/blob/12f6f91adcc56be53c00db36647c6e4923222586/har_dump.py#L30
- Clear the flows after each dump to prevent duplication.

### Customizing the Dump Interval

By default, the HAR dump interval is set to **10 seconds**. To change this:

1. Open the `har_dump.py` script in a text editor. 
2. Locate the line:
  - https://github.com/thenisvan/mitmproxy-periodicalHarDump/blob/12f6f91adcc56be53c00db36647c6e4923222586/har_dump.py#L30

```python
self.dump_interval_seconds = 10  # Set interval to 10 seconds
```

3. Change `10` to your desired number of seconds.

```python
self.dump_interval_seconds = 3600  # Set interval to 1 hour
```

## Output

HAR files are saved in the mitmproxy configuration directory (`~/.mitmproxy/`) with filenames in the format:

```
har_dump_YYYY-MM-DD_HH-MM-SS.har
```

**Example:**

```
~/.mitmproxy/har_dump_2023-10-15_12-30-00.har
```

- **Flow Filtering**: Currently, the addon saves all HTTP flows. If you want to filter which flows are saved, you can modify the `self.filt` attribute with a mitmproxy filter expression.

```python
self.filt = flowfilter.parse("~u example.com")  # Only save flows to example.com
```
---
# About Certificates

Mitmproxy can decrypt encrypted traffic on the fly, as long as the client trusts
mitmproxy's built-in certificate authority. Usually this means that the mitmproxy CA
certificate has to be installed on the client device.

## Quick Setup

By far the easiest way to install the mitmproxy CA certificate is to use the
built-in certificate installation app. To do this, start mitmproxy and
configure your target device with the correct proxy settings. Now start a
browser on the device, and visit the magic domain [mitm.it](http://mitm.it/). You should see
something like this:

[{{< figure src="/certinstall-webapp.png" class="has-border" >}}](https://docs.mitmproxy.org/stable/certinstall-webapp.png)

Click on the relevant icon, follow the setup instructions for the platform
you're on and you are good to go.

## The mitmproxy certificate authority

The first time mitmproxy is run, it creates the keys for a certificate
authority (CA) in the config directory (`~/.mitmproxy` by default).
This CA is used for on-the-fly generation of dummy certificates for each visited website.
Since your browser won't trust the mitmproxy CA out of the box, you will either need to click through a TLS certificate
warning on every domain, or install the CA certificate once so that it is trusted.

The following files are created:

| Filename              | Contents                                                                             |
| --------------------- | ------------------------------------------------------------------------------------ |
| mitmproxy-ca.pem      | The certificate **and the private key** in PEM format.                               |
| mitmproxy-ca-cert.pem | The certificate in PEM format. Use this to distribute on most non-Windows platforms. |
| mitmproxy-ca-cert.p12 | The certificate in PKCS12 format. For use on Windows.                                |
| mitmproxy-ca-cert.cer | Same file as .pem, but with an extension expected by some Android devices.           |

For security reasons, the mitmproxy CA is generated uniquely on the first start and
is not shared between mitmproxy installations on different devices. This makes sure
that other mitmproxy users cannot intercept your traffic.

### Installing the mitmproxy CA certificate manually

Sometimes using the [quick install app](#quick-setup) is not an option and you need to install the CA manually.
Below is a list of pointers to manual certificate installation
documentation for some common platforms. The mitmproxy CA cert is located in
`~/.mitmproxy` after it has been generated at the first start of mitmproxy.

- curl on the command line:  
  `curl --proxy 127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com/`
- wget on the command line:  
  `wget -e https_proxy=127.0.0.1:8080 --ca-certificate ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com/`
- [macOS](https://support.apple.com/guide/keychain-access/add-certificates-to-a-keychain-kyca2431/mac)
- [macOS (automated)](https://www.dssw.co.uk/reference/security.html):
  `sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem`
- [Ubuntu/Debian]( https://askubuntu.com/questions/73287/how-do-i-install-a-root-certificate/94861#94861)
- [Fedora](https://docs.fedoraproject.org/en-US/quick-docs/using-shared-system-certificates/#proc_adding-new-certificates)
- [Mozilla Firefox](https://wiki.mozilla.org/MozillaRootCertificate#Mozilla_Firefox)
- [Chrome on Linux](https://stackoverflow.com/a/15076602/198996)
- [iOS](http://jasdev.me/intercepting-ios-traffic)  
  On recent iOS versions you also need to enable full trust for the mitmproxy
  root certificate:
    1. Go to Settings > General > About > Certificate Trust Settings.
    2. Under "Enable full trust for root certificates", turn on trust for
       the mitmproxy certificate.
- [iOS Simulator](https://github.com/ADVTOOLS/ADVTrustStore#how-to-use-advtruststore)
- [Java](https://docs.oracle.com/cd/E19906-01/820-4916/geygn/index.html):  
  `sudo keytool -importcert -alias mitmproxy -storepass changeit -keystore $JAVA_HOME/lib/security/cacerts -trustcacerts -file ~/.mitmproxy/mitmproxy-ca-cert.pem`
- [Android/Android Simulator](http://wiki.cacert.org/FAQ/ImportRootCert#Android_Phones_.26_Tablets)
- [Windows](https://web.archive.org/web/20160612045445/http://windows.microsoft.com/en-ca/windows/import-export-certificates-private-keys#1TC=windows-7)
- [Windows (automated)](https://technet.microsoft.com/en-us/library/cc732443.aspx):  
  `certutil -addstore root mitmproxy-ca-cert.cer`






## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the mitmproxy team for their powerful and flexible proxy tool.

## Contact

For any questions or suggestions, please open an issue 
