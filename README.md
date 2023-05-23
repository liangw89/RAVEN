# RAVEN
For PETS 2023 paper: *RAVEN: Stateless Rapid IP Address Variation for Enterprise Networks*


#### Traces
- **Source**: traces.zip
- **Trace format**: time, packet size * direction, subflow ID 
- **Traces/mon**: 100 monitored sites, 20 instances each (trace name: "siteID_instID")
- **Traces/unmon**: 10,000 monitored sites (trace name: "siteID_0")

#### Chrome patch

- **Source**: chrome/raven_quic.patch

#### P4 code

- **Source**: p4/
