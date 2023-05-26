 # RAVEN
For PETS 2023 paper: *RAVEN: Stateless Rapid IP Address Variation for Enterprise Networks*


#### Traces
- **Source**: `traces.zip`
- **Trace format**: time, packet size * direction, subflow ID 
- **Traces/mon**: 100 monitored sites, 20 instances each (trace name: "siteID_instID")
- **Traces/unmon**: 10,000 monitored sites (trace name: "siteID_0")

### RAVEN defense and adaptive attack simulation
- **Source**: `code/`
- Check `code/README.md` for details

#### Chrome patch

- **Source**: `chrome/raven_quic.patch`
- Check `chrome/README.md` for details

#### P4 code

- **Source**: `p4/`
- **Setup**: Barefoot SDE 9.3.2

To compile the code, install Barefoot SDE 9.3.2 in a VM and run
```
./p4_build.sh -p pinot_quic.p4 (may take > 20 mins)
./run_tofino_model.sh -p pinot_quic
./run_switchd.sh -p pinot_quic
python ctr56tcprotate.py
```
To test the code, one should use a real tofino switch connected to a IPv6 network. and:

(1) `pinot_quic.p4`: Set `hdr.ethernet.dst_addr` to the client's ethernet address

(2) `header.h`: Set `PUB_NET_PREFIX`, `NET_PREFIX` and `SUB_NET`according to the assigned IPv6 network.
