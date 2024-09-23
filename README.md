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
- Save the captured flows into a HAR file at regular intervals (edit `har_dump.py:30).[https://github.com/thenisvan/mitmproxy-periodicalHarDump/blob/12f6f91adcc56be53c00db36647c6e4923222586/har_dump.py#L30]
- Clear the flows after each dump to prevent duplication.

### Customizing the Dump Interval

By default, the HAR dump interval is set to **10 seconds**. To change this:

1. Open the `har_dump.py` script in a text editor. 
2. Locate the line: [https://github.com/thenisvan/mitmproxy-periodicalHarDump/blob/12f6f91adcc56be53c00db36647c6e4923222586/har_dump.py#L30]

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

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the mitmproxy team for their powerful and flexible proxy tool.

## Contact

For any questions or suggestions, please open an issue 
