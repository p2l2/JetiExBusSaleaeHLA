# 
# Jeti ExBus High Level Analyzer (EXBUS-HLA)

Saleae Logic2 High Level Analyzer to decode the EX Bus protocol by JETImodel

EX Bus is the most current protocol used by JETI and is the only protocol this HLA decodes. 
There are also two older protocols, namely EX Telemetry and the version 1 JetiBox text messages.
None of these are supported by this HLA.

Copyright 2024, Markus Pfaff, [P2L2 GmbH, Austria](https://www.p2l2.com/)
  
## Getting started

1. Install the JetiExBus Analyzer in Logic2 from the extensions menu
2. Create an Async Serial analyzer, baud rate: 125000, 8 bits, 1 stop bit, no parity, LSB sent first, non-inverted signalling, "Normal" mode. For this setting a sampling rate of 20MS/s is good enough.
3. Jeti EX Bus comes at two possible baud rates: 125k and 250k. Still in practice only the 125k version seems to be used. You might need to switch to 250k baud rate in some cases.
4. Create a JetiExBus Analyzer in Logic2 using the Async Serial Analyzer just created as the Input Analyzer.

## Decoding Features

* Channel packets sent by a master (e.g. a JETI receiver)
* Telemetry request packets sent by a master
* Telemetry response packets sent by a slave (e.g. a sensor device)
  * Text telemetry packets
  * Data telemetry packets

![Logic2 using the JetiExBus HLA](/pic/Logic2JetiExBusAnalyzer.png)

## Missing/ToDo

* Message packets
* JetiBox packets
* Simple text messages