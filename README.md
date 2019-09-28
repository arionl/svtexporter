# SVTExporter

SVTExporter talks to the API of a SimpliVity OVC to pull information about used capacity on one or more nodes. It does not maintain any state - it expects to be scraped periodically through Prometheus. 

**Note:** Depending on how long each scrape operation takes, you may not get data back. Please review the notes below about `scrape_interval` and `scrape_timeout` carefully.


## Running

Launch with `python3 svtexporter.py` and make sure you have `config.ini` in the same directory.

## Configuration

Expects a file called `config.ini` in the same directory as the exporter with the following info:

```[SVT]
HOST=ovc1 # SimpliVity IP that has the OVC API available
USERNAME=
PASSWORD=
PORT=9388 # port to bind to
```

## Prometheus

Example of how the exporter can be configured in Prometheus:

```
- job_name: svtexporter
  honor_timestamps: true
  scrape_interval: 30s
  scrape_timeout: 20s
  metrics_path: /metrics
  scheme: http
  static_configs:
  - targets:
    - host:9388
```

You will need to tune `scrape_interval` and `scrape_timeout` based on how long it takes the SVTExporter to collect metrics. You can request `/metrics` manually to see this or put in some reasonable defaults and monitor Prometheus' Targets status page to see if it completes successfully.
