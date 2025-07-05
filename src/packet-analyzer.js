class PacketAnalyzer {
  constructor() {}

  analyzePacket(packetData, channel) {
    try {
      const buffer = Buffer.from(packetData, "hex");
      const analysis = {
        rawData: packetData,
        totalLength: buffer.length,
        layers: [],
        errors: [],
        timestamp: new Date().toISOString(),
      };
      this.analyzeLayers(buffer, analysis, channel);
      return analysis;
    } catch (error) {
      return {
        rawData: packetData,
        error: error.message,
        layers: [],
        timestamp: new Date().toISOString(),
      };
    }
  }

  analyzeLayers(buffer, analysis, channel) {
    let offset = 0;

    // 1. IEEE 802.15.4
    const ieeeLayer = this.analyzeIEEE802154(buffer, offset, channel);
    analysis.layers.push(ieeeLayer);
    offset += ieeeLayer.totalBytes;

    // 2. IEEE 802.15.4 Security (nếu có)
    let securityLevel = null;
    if (ieeeLayer.hasSecurityHeader) {
      const secLayer = this.analyzeIEEE802154Security(buffer, offset);
      if (secLayer) {
        analysis.layers.push(secLayer);
        offset += secLayer.totalBytes;
        for (const field of secLayer.fields) {
          if (field.name === "Security Control") {
            securityLevel = parseInt(field.value, 16) & 0x07;
          }
        }
      }
    }

    // 3. 6Lowpan
    const sixlowpanLayer = this.analyze6Lowpan(buffer, offset);
    if (sixlowpanLayer) {
      analysis.layers.push(sixlowpanLayer);
      offset += sixlowpanLayer.totalBytes;
    }

    // 4. Lowpan UDP (nếu có)
    const udpLayer = this.analyzeLowpanUDP(buffer, offset);
    if (udpLayer) {
      analysis.layers.push(udpLayer);
      offset += udpLayer.totalBytes;
    }

    // 5. ICMPv6 (nếu có)
    const icmpLayer = this.analyzeICMPv6(buffer, offset);
    if (icmpLayer) {
      analysis.layers.push(icmpLayer);
      offset += icmpLayer.totalBytes;
    }

    // 6. MLE Security (nếu có)
    const mleSecLayer = this.analyzeMLESecurity(buffer, offset);
    if (mleSecLayer) {
      analysis.layers.push(mleSecLayer);
      offset += mleSecLayer.totalBytes;
    }

    // 7. MLE (nếu có)
    const mleLayer = this.analyzeMLE(buffer, offset);
    if (mleLayer) {
      analysis.layers.push(mleLayer);
      offset += mleLayer.totalBytes;
    }

    // 8. Application Payload (trừ MIC nếu có)
    let micLen = 0;
    if (securityLevel === 1 || securityLevel === 5) micLen = 4;
    else if (securityLevel === 2 || securityLevel === 6) micLen = 8;
    else if (securityLevel === 3 || securityLevel === 7) micLen = 16;

    const payloadLen = buffer.length - offset - micLen;
    if (payloadLen > 0) {
      analysis.layers.push({
        name: "Application Payload",
        totalBytes: payloadLen,
        expanded: true,
        fields: [{ name: "Length", value: `${payloadLen} bytes` }],
      });
      offset += payloadLen;
    }

    // 9. MAC encryption MIC (nếu có)
    if (micLen > 0 && buffer.length >= micLen) {
      const micOffset = buffer.length - micLen;
      const micLayer = this.analyzeMacMic(buffer, micOffset, securityLevel);
      if (micLayer) analysis.layers.push(micLayer);
    }
  }

  // --- IEEE 802.15.4 ---
  analyzeIEEE802154(buffer, offset, channel) {
    let pos = offset;
    const phrLen = channel >= 11 && channel <= 26 ? 1 : 2;
    const layer = {
      name: "IEEE 802.15.4",
      totalBytes: 0,
      expanded: true,
      fields: [],
    };

    // PHY Header
    const phr = buffer[pos];
    layer.fields.push({
      name: "PHY Header",
      type: 'expandable',
      value: `0x${phr.toString(16).padStart(2, "0").toUpperCase()}`,
      subfields: [
        {
          name: "Packet Length",
          value: phr,
          binaryDisplay: phr
            .toString(2)
            .padStart(8, "0")
            .replace(/(.{4})/g, "$1 "),
          description: `${phr} bytes`,
        },
      ],
    });
    pos += phrLen;

    // Frame Control
    const fc = buffer.readUInt16LE(pos);
    const fcBin = fc.toString(2).padStart(16, "0");
    layer.fields.push({
      name: "Frame Control",
      type: "expandable",
      value: `0x${fc.toString(16).padStart(4, "0").toUpperCase()}`,
      subfields: [
        {
          name: "Frame Type",
          value: fc & 0x07,
          description: ["Beacon", "Data", "Ack", "Command"][fc & 0x07],
          binaryDisplay: subfieldBinaryDisplay(fcBin, 13, 15)
        },
        {
          name: "Security Enabled",
          value: (fc >> 3) & 1,
          description: (fc >> 3) & 1 ? "true" : "false",
          binaryDisplay: subfieldBinaryDisplay(fcBin, 12, 12)
        },
        {
          name: "Frame Pending",
          value: (fc >> 4) & 1,
          description: (fc >> 4) & 1 ? "true" : "false",
          binaryDisplay: subfieldBinaryDisplay(fcBin, 11, 11)
        },
        {
          name: "Ack Required",
          value: (fc >> 5) & 1,
          description: (fc >> 5) & 1 ? "true" : "false",
          binaryDisplay: subfieldBinaryDisplay(fcBin, 10, 10)
        },
        {
          name: "PAN ID Compression",
          value: (fc >> 6) & 1,
          description: (fc >> 6) & 1 ? "true" : "false",
          binaryDisplay: subfieldBinaryDisplay(fcBin, 9, 9)
        },
        {
          name: "Frame Version",
          value: (fc >> 12) & 0x03,
          description: ["2003", "2006", "2015", "Reserved"][(fc >> 12) & 0x03],
          binaryDisplay: subfieldBinaryDisplay(fcBin, 2, 3)
        },
        {
          name: "Reserved",
          value: (fc >> 7) & 0x07,
          description: `0x${((fc >> 7) & 0x07).toString(16).toUpperCase().padStart(2, '0')}`,
          binaryDisplay: subfieldBinaryDisplay(fcBin, 6, 8)
        },
        {
          name: "Dest Addr Mode",
          value: (fc >> 10) & 0x03,
          description: ["None", "Reserved", "Short", "Ext"][(fc >> 10) & 0x03],
          binaryDisplay: subfieldBinaryDisplay(fcBin, 4, 5)
        },
        {
          name: "Src Addr Mode",
          value: (fc >> 14) & 0x03,
          description: ["None", "Reserved", "Short", "Ext"][(fc >> 14) & 0x03],
          binaryDisplay: subfieldBinaryDisplay(fcBin, 0, 1)
        },
      ],
    });
    pos += 2;

    // Sequence
    layer.fields.push({
      name: "Sequence",
      value: `0x${buffer[pos].toString(16).padStart(2, "0").toUpperCase()}`,
    });
    pos += 1;

    // Addressing (ĐÚNG THỨ TỰ)
    const destAddrMode = (fc >> 10) & 0x03;
    const srcAddrMode = (fc >> 14) & 0x03;
    const panIdCompression = (fc >> 6) & 0x01;

    // Destination PAN ID
    if (destAddrMode !== 0) {
      const destPanId = buffer.readUInt16LE(pos);
      layer.fields.push({
        name: "Destination PAN ID",
        value: `0x${destPanId.toString(16).padStart(4, "0").toUpperCase()}`,
      });
      pos += 2;
    }
    // Short/Long Destination Address
    if (destAddrMode === 2) {
      const destAddr = buffer.readUInt16LE(pos);
      layer.fields.push({
        name: "Short Destination Address",
        value: `0x${destAddr.toString(16).padStart(4, "0").toUpperCase()}`,
      });
      pos += 2;
    } else if (destAddrMode === 3) {
      const destAddr = buffer.subarray(pos, pos + 8);
      const destAddrHex = Array.from(destAddr)
        .reverse()
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
      layer.fields.push({
        name: "Long Destination Address",
        value: destAddrHex,
      });
      pos += 8;
    }
    // Source PAN ID (nếu không compressed)
    if (srcAddrMode !== 0 && !panIdCompression) {
      const srcPanId = buffer.readUInt16LE(pos);
      layer.fields.push({
        name: "Source PAN ID",
        value: `0x${srcPanId.toString(16).padStart(4, "0").toUpperCase()}`,
      });
      pos += 2;
    }
    // Short/Long Source Address
    if (srcAddrMode === 2) {
      const srcAddr = buffer.readUInt16LE(pos);
      layer.fields.push({
        name: "Short Source Address",
        value: `0x${srcAddr.toString(16).padStart(4, "0").toUpperCase()}`,
      });
      pos += 2;
    } else if (srcAddrMode === 3) {
      const srcAddr = buffer.subarray(pos, pos + 8);
      const srcAddrHex = Array.from(srcAddr)
        .reverse()
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
      layer.fields.push({ name: "Long Source Address", value: srcAddrHex });
      pos += 8;
    }

    layer.totalBytes = pos - offset;
    layer.hasSecurityHeader = ((fc >> 3) & 1) === 1;
    return layer;
  }

  // --- IEEE 802.15.4 Security ---
  analyzeIEEE802154Security(buffer, offset) {
    let pos = offset;
    const layer = {
      name: "IEEE 802.15.4 Security",
      totalBytes: 0,
      expanded: true,
      fields: [],
    };
    const securityControl = buffer[pos];
    const scBin = securityControl.toString(2).padStart(8, "0");
    const securityLevel = securityControl & 0x07;
    const keyIdMode = (securityControl >> 3) & 0x03;

    layer.fields.push({
      name: "Security Control",
      type: "expandable",
      value: `0x${securityControl.toString(16).padStart(2, "0").toUpperCase()}`,
      subfields: [
        {
          name: "Security Level",
          value: securityLevel,
          description: this.getSecurityLevelDescription(securityLevel),
          binaryDisplay: subfieldBinaryDisplay(scBin, 5, 7, 4)
        },
        {
          name: "Key Identifier Mode",
          value: keyIdMode,
          description: this.getKeyIdModeDescription(keyIdMode),
          binaryDisplay: subfieldBinaryDisplay(scBin, 3, 4, 4)
        },
      ],
    });
    pos += 1;

    // Frame Counter
    const frameCounter = buffer.readUInt32LE(pos);
    layer.fields.push({
      name: "Frame Counter",
      value: `0x${frameCounter.toString(16).padStart(8, "0").toUpperCase()}`,
    });
    pos += 4;

    // Key Source (nếu có)
    if (keyIdMode === 2) {
      layer.fields.push({
        name: "Key Source (4 byte)",
        value: buffer
          .subarray(pos, pos + 4)
          .toString("hex")
          .toUpperCase(),
      });
      pos += 4;
    } else if (keyIdMode === 3) {
      layer.fields.push({
        name: "Key Source (8 byte)",
        value: buffer
          .subarray(pos, pos + 8)
          .toString("hex")
          .toUpperCase(),
      });
      pos += 8;
    }
    // Key Index
    if (keyIdMode > 0) {
      layer.fields.push({
        name: "Key Index",
        value: `0x${buffer[pos].toString(16).padStart(2, "0").toUpperCase()}`,
      });
      pos += 1;
    }

    layer.totalBytes = pos - offset;
    return layer;
  }

  // --- 6Lowpan ---
  analyze6Lowpan(buffer, offset) {
    let pos = offset;
    if (buffer.length <= pos) return null;
    const dispatch = buffer[pos];

    // 1. Mesh Header (10xxxxxx)
    if ((dispatch & 0xC0) === 0x80) {
        const hopsLeft = dispatch & 0x0F;
        if (buffer.length < pos + 1 + 2 + 2) return null;
        const originatorAddr = buffer.subarray(pos + 1, pos + 3);
        const finalAddr = buffer.subarray(pos + 3, pos + 5);

        // Hiển thị nhị phân dispatch byte chia nhóm 4 bit
        const dispatchBin = dispatch.toString(2).padStart(8, '0');

        return {
            name: '6lowpan',
            totalBytes: 5,
            fields: [
                {
                    name: 'Dispatch Byte',
                    type: 'expandable',
                    value: `0x${dispatch.toString(16).padStart(2, '0').toUpperCase()}`,
                    subfields: [
                        {
                            name: 'Hops Left',
                            value: `0x${hopsLeft.toString(16).padStart(2, '0').toUpperCase()}`,
                            description: `${parseInt(dispatchBin.slice(4, 8), 2)}`,
                            binaryDisplay: subfieldBinaryDisplay(dispatchBin, 4, 7, 4)
                        }
                    ]
                },
                { name: 'Originator Address', value: originatorAddr.toString('hex').toUpperCase() },
                { name: 'Final Address', value: finalAddr.toString('hex').toUpperCase() }
            ]
        };
    }


    // 2. Fragmentation Header (11xxxxxx)
    // Fragmentation Header: FRAG1 (11000xxx, 0xC0–0xDF)
if ((dispatch & 0xF8) === 0xC0 && buffer.length >= pos + 4) {
    const fragCtrl = (dispatch << 8) | buffer[pos + 1];
    const fragCtrlBin = fragCtrl.toString(2).padStart(16, '0');
    // Fragment Type: 5 bit đầu (0-4), Datagram Size: 11 bit tiếp theo (5-15)
    const fragmentType = (fragCtrl >> 11) & 0x1F;
    const fragmentTypeDesc = fragmentType === 24 ? 'First fragment (FRAG1)' : 'Unknown';
    const datagramSize = fragCtrl & 0x7FF; // 11 bit cuối
    const datagramTag = (buffer[pos + 2] << 8) | buffer[pos + 3];

    return {
        name: '6lowpan',
        totalBytes: 4,
        fields: [
            {
                name: 'Fragment Control',
                type: 'expandable',
                value: `0x${fragCtrl.toString(16).toUpperCase()}`,
                subfields: [
                    { 
                        name: 'Fragment Type',
                        value: fragmentType,
                        description: fragmentTypeDesc,
                        binaryDisplay: subfieldBinaryDisplay(fragCtrlBin, 0, 4)
                    },
                    {
                        name: 'Datagram Size', 
                        value: datagramSize,
                        description: `0x${datagramSize.toString(16).toUpperCase().padStart(3, '0')}`,
                        binaryDisplay: subfieldBinaryDisplay(fragCtrlBin, 5, 15)
                    }
                ]
            },
            { name: 'Datagram Tag', value: `0x${datagramTag.toString(16).toUpperCase().padStart(4, '0')}` }
        ]
    };
}

// Fragmentation Header: FRAGN (11100xxx, 0xE0–0xFF)
if ((dispatch & 0xF8) === 0xE0 && buffer.length >= pos + 5) {
    const fragCtrl = (dispatch << 8) | buffer[pos + 1];
    const fragCtrlBin = fragCtrl.toString(2).padStart(16, '0');
    // Fragment Type: 5 bit đầu (0-4), Datagram Size: 11 bit tiếp theo (5-15)
    const fragmentType = (fragCtrl >> 11) & 0x1F;
    const fragmentTypeDesc = fragmentType === 28 ? 'Next fragment (FRAGN)' : 'Unknown';
    const datagramSize = fragCtrl & 0x7FF; // 11 bit cuối
    const datagramTag = (buffer[pos + 2] << 8) | buffer[pos + 3];
    const datagramOffset = buffer[pos + 4];

    return {
        name: '6lowpan',
        totalBytes: 5,
        fields: [
            {
                name: 'Fragment Control',
                type: 'expandable',
                value: `0x${fragCtrl.toString(16).toUpperCase()}`,
                subfields: [
                    { 
                        name: 'Fragment Type',
                        value: fragmentType,
                        description: fragmentTypeDesc,
                        binaryDisplay: subfieldBinaryDisplay(fragCtrlBin, 0, 4)
                    },
                    { 
                        name: 'Datagram Size',
                        value: datagramSize,
                        description: `0x${datagramSize.toString(16).toUpperCase().padStart(3, '0')}`,
                        binaryDisplay: subfieldBinaryDisplay(fragCtrlBin, 5, 15)
                    }
                ]
            },
            { name: 'Datagram Tag', value: `0x${datagramTag.toString(16).toUpperCase().padStart(4, '0')}` },
            { name: 'Datagram Offset', value: datagramOffset }
        ]
    };
}



    // 3. IPHC (011xxxxx, 0x60–0x7F)
    if ((dispatch & 0xE0) === 0x60 && buffer.length >= pos + 2) {
        const iphc = buffer.readUInt16BE(pos);
        const tf = (iphc >> 11) & 0x03;
        const nh = (iphc >> 10) & 0x01;
        const hlim = (iphc >> 8) & 0x03;
        const cid = (iphc >> 7) & 0x01;
        const sac = (iphc >> 6) & 0x01;
        const sam = (iphc >> 4) & 0x03;
        const m = (iphc >> 3) & 0x01;
        const dac = (iphc >> 2) & 0x01;
        const dam = iphc & 0x03;

        const iphcBin = iphc.toString(2).padStart(16, '0');

        let fields = [{
            name: 'IPHC Base Encoding',
            type: 'expandable',
            value: `0x${iphc.toString(16).padStart(4, '0').toUpperCase()}`,
            subfields: [
                { 
                    name: 'Traffic and Flow',
                    value: tf,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 3, 4)
                },
                { 
                    name: 'Next Header', 
                    value: nh,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 5, 5)
                },
                { 
                    name: 'Hop Limit', 
                    value: hlim,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 6, 7) 
                },
                { 
                    name: 'Context ID', 
                    value: cid,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 8, 8)
                },
                { 
                    name: 'Source Compression', 
                    value: sac,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 9, 9)
                },
                { 
                    name: 'Source Address Mode', 
                    value: sam,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 10, 11)
                },
                { 
                    name: 'Multicast Compression', 
                    value: m,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 12, 12)
                },
                { 
                    name: 'Destination Compression', 
                    value: dac,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 13, 13)
                },
                { 
                    name: 'Destination Address Mode', 
                    value: dam,
                    binaryDisplay: subfieldBinaryDisplay(iphcBin, 14, 15)
                }
            ]
        }];
        pos += 2;

        if (cid === 1) {
            if (buffer.length < pos + 1) return null;
            fields.push({ name: 'Context ID Field', value: `0x${buffer[pos].toString(16).padStart(2, '0').toUpperCase()}` });
            pos += 1;
        }
        if (tf === 0) {
            if (buffer.length < pos + 4) return null;
            fields.push({ name: 'Traffic and Flow Field', value: buffer.subarray(pos, pos + 4).toString('hex').toUpperCase() });
            pos += 4;
        } else if (tf === 1) {
            if (buffer.length < pos + 1) return null;
            fields.push({ name: 'Traffic and Flow Field', value: buffer[pos].toString(16).padStart(2, '0').toUpperCase() });
            pos += 1;
        } else if (tf === 2) {
            if (buffer.length < pos + 3) return null;
            fields.push({ name: 'Traffic and Flow Field', value: buffer.subarray(pos, pos + 3).toString('hex').toUpperCase() });
            pos += 3;
        }
        if (sam !== 3) {
            const srcLen = { 0: 16, 1: 8, 2: 2 }[sam] || 0;
            if (buffer.length < pos + srcLen) return null;
            fields.push({ name: 'Source Address', value: buffer.subarray(pos, pos + srcLen).toString('hex').toUpperCase() });
            pos += srcLen;
        }
        if (m === 0) {
            if (dam !== 3) {
                const destLen = { 0: 16, 1: 8, 2: 2 }[dam] || 0;
                if (buffer.length < pos + destLen) return null;
                fields.push({ name: 'Destination Address', value: buffer.subarray(pos, pos + destLen).toString('hex').toUpperCase() });
                pos += destLen;
            }
        } else {
            const destLen = { 0: 16, 1: 6, 2: 4, 3: 1 }[dam] || 0;
            if (buffer.length < pos + destLen) return null;
            fields.push({ name: 'Destination Address', value: buffer.subarray(pos, pos + destLen).toString('hex').toUpperCase() });
            pos += destLen;
        }
        return { name: '6lowpan', totalBytes: pos - offset, fields };
    }

    // 4. ESC (Extension Dispatch, RFC 8066)
    if ((dispatch === 0x7E || dispatch === 0x7F) && buffer.length >= pos + 2) {
        const escType = buffer[pos + 1];
        return {
            name: '6lowpan',
            totalBytes: 2,
            fields: [
                { name: 'Dispatch Byte', value: `0x${dispatch.toString(16).padStart(2, '0').toUpperCase()}`, description: 'ESC (Extension Dispatch)' },
                { name: 'ESC Extension Type', value: `0x${escType.toString(16).padStart(2, '0').toUpperCase()}` }
            ]
        };
    }

    // 5. IPv6 uncompressed (0x41), HC1 (0x42), BC0 (0x50)
    if (dispatch === 0x41) {
        return {
            name: '6lowpan',
            totalBytes: 1,
            fields: [
                { name: 'Dispatch Byte', value: '0x41', description: 'IPv6 Uncompressed' }
            ]
        };
    }
    if (dispatch === 0x42) {
        return {
            name: '6lowpan',
            totalBytes: 1,
            fields: [
                { name: 'Dispatch Byte', value: '0x42', description: 'LOWPAN_HC1 (deprecated)' }
            ]
        };
    }
    if (dispatch === 0x50) {
        return {
            name: '6lowpan',
            totalBytes: 1,
            fields: [
                { name: 'Dispatch Byte', value: '0x50', description: 'LOWPAN_BC0 (Broadcast)' }
            ]
        };
    }

    // 6. Paging Dispatch (RFC 8025)
    if ((dispatch & 0xF0) === 0xF0) {
        return {
            name: '6lowpan',
            totalBytes: 1,
            fields: [
                { name: 'Dispatch Byte', value: `0x${dispatch.toString(16).padStart(2, '0').toUpperCase()}`, description: 'Paging Dispatch (RFC 8025)' }
            ]
        };
    }

    
    return null;
}


  // --- Lowpan UDP ---
  analyzeLowpanUDP(buffer, offset) {
    let pos = offset;
    if (buffer.length <= pos + 7) return null;
    const nhc = buffer[pos];
    if ((nhc & 0xf8) === 0xf0) {
      const layer = {
        name: "Lowpan UDP",
        totalBytes: 7,
        expanded: true,
        fields: [],
      };
      layer.fields.push({
        name: "Next Header Encoding",
        value: `0x${nhc.toString(16).padStart(2, "0").toUpperCase()}`,
      });
      pos += 1;
      layer.fields.push({
        name: "Source Port",
        value: `0x${buffer
          .readUInt16BE(pos)
          .toString(16)
          .padStart(4, "0")
          .toUpperCase()}`,
      });
      layer.fields.push({
        name: "Dest Port",
        value: `0x${buffer
          .readUInt16BE(pos + 2)
          .toString(16)
          .padStart(4, "0")
          .toUpperCase()}`,
      });
      layer.fields.push({
        name: "Checksum",
        value: `0x${buffer
          .readUInt16BE(pos + 4)
          .toString(16)
          .padStart(4, "0")
          .toUpperCase()}`,
      });
      pos += 6;
      layer.totalBytes = pos - offset;
      return layer;
    }
    return null;
  }

  // --- ICMPv6 ---
  analyzeICMPv6(buffer, offset) {
    if (buffer.length < offset + 4) return null;
    const type = buffer[offset];
    // ICMPv6: Type 128 = Echo Request, 129 = Echo Reply, etc.
    if (type === 0x80 || type === 0x81 || type === 0x82 || type === 0x85) {
      return {
        name: "ICMPv6",
        totalBytes: 4,
        expanded: true,
        fields: [
          {
            name: "Type",
            value: `0x${type.toString(16).padStart(2, "0").toUpperCase()}`,
          },
          {
            name: "Code",
            value: `0x${buffer[offset + 1]
              .toString(16)
              .padStart(2, "0")
              .toUpperCase()}`,
          },
          {
            name: "Checksum",
            value: `0x${buffer
              .readUInt16BE(offset + 2)
              .toString(16)
              .padStart(4, "0")
              .toUpperCase()}`,
          },
        ],
      };
    }
    return null;
  }

  // --- MLE Security ---
  analyzeMLESecurity(buffer, offset) {
    let pos = offset;
    if (buffer.length <= pos + 11) return null;
    if (buffer[pos] === 0x00) {
      // Security Suite
      const layer = {
        name: "MLE Security",
        totalBytes: 11,
        expanded: true,
        fields: [],
      };
      layer.fields.push({
        name: "Security Suite",
        value: `0x${buffer[pos].toString(16).padStart(2, "0").toUpperCase()}`,
      });
      pos += 1;
      layer.fields.push({
        name: "Security Control",
        value: `0x${buffer[pos].toString(16).padStart(2, "0").toUpperCase()}`,
      });
      pos += 1;
      layer.fields.push({
        name: "Frame Counter",
        value: `0x${buffer
          .readUInt32LE(pos)
          .toString(16)
          .padStart(8, "0")
          .toUpperCase()}`,
      });
      pos += 4;
      layer.fields.push({
        name: "Full Sequence",
        value: `0x${buffer
          .readUInt32LE(pos)
          .toString(16)
          .padStart(8, "0")
          .toUpperCase()}`,
      });
      pos += 4;
      layer.fields.push({
        name: "Key Index",
        value: `0x${buffer[pos].toString(16).padStart(2, "0").toUpperCase()}`,
      });
      pos += 1;
      layer.totalBytes = pos - offset;
      return layer;
    }
    return null;
  }

  // --- MLE ---
  analyzeMLE(buffer, offset) {
    if (buffer.length < offset + 2) return null;
    const command = buffer[offset];
    if (command >= 0x01 && command <= 0x0f) {
      return {
        name: "MLE",
        totalBytes: buffer.length - offset,
        expanded: true,
        fields: [
          {
            name: "Command",
            value: `0x${command.toString(16).padStart(2, "0").toUpperCase()}`,
          },
          {
            name: "Raw",
            value: buffer.subarray(offset).toString("hex").toUpperCase(),
          },
        ],
      };
    }
    return null;
  }

  // --- Application Payload ---
  analyzePayload(buffer, offset) {
    const remaining = buffer.length - offset;
    if (remaining <= 0) return null;
    return {
      name: "Application Payload",
      totalBytes: remaining,
      expanded: true,
      fields: [{ name: "Length", value: `${remaining} bytes` }],
    };
  }

  // --- MAC encryption MIC ---
  analyzeMacMic(buffer, offset, securityLevel) {
    let micLen = 0;
    if (securityLevel === 1 || securityLevel === 5) micLen = 4;
    else if (securityLevel === 2 || securityLevel === 6) micLen = 8;
    else if (securityLevel === 3 || securityLevel === 7) micLen = 16;
    if (micLen && buffer.length >= offset + micLen) {
      return {
        name: "MAC encryption MIC",
        totalBytes: micLen,
        expanded: true,
        fields: [
          {
            name: "MAC MIC",
            value: buffer
              .subarray(offset, offset + micLen)
              .toString("hex")
              .toUpperCase(),
          },
        ],
      };
    }
    return null;
  }

  // --- Helper functions ---
  getSecurityLevelDescription(level) {
    const descriptions = {
      0: "None",
      1: "MIC-32",
      2: "MIC-64",
      3: "MIC-128",
      4: "ENC",
      5: "Encrypted, 4 byte MIC",
      6: "ENC-MIC-64",
      7: "ENC-MIC-128",
    };
    return descriptions[level] || "Reserved";
  }
  getKeyIdModeDescription(mode) {
    const descriptions = {
      0: "No source",
      1: "Key Index",
      2: "4-byte Key Source + Key Index",
      3: "8-byte Key Source + Key Index",
    };
    return descriptions[mode] || "Reserved";
  }
}

/**
 * Tạo chuỗi hiển thị bit cho subfield, chia nhóm 4 bit, các bit không liên quan là dấu chấm.
 * @param {string} bin - Chuỗi nhị phân (ví dụ: '1110011110111000', 16 ký tự).
 * @param {number} from - Vị trí bit bắt đầu (0 là bit trái nhất, bên trái).
 * @param {number} to - Vị trí bit kết thúc (0 <= from <= to < bin.length).
 * @param {number} [group=4] - Số bit mỗi nhóm (mặc định 4).
 * @returns {string} Chuỗi hiển thị bit, chia nhóm, ví dụ: '111. .... .... ....'
 */
function subfieldBinaryDisplay(bin, from, to, group = 4) {
  // Đảm bảo bin đủ độ dài
  const n = bin.length;
  let arr = Array(n).fill('.');
  for (let i = from; i <= to; i++) arr[i] = bin[i];
  // Ghép lại thành chuỗi, chia nhóm group bit bằng dấu cách
  let result = '';
  for (let i = 0; i < n; i += group) {
    result += arr.slice(i, i + group).join('') + ' ';
  }
  return result.trim();
}

module.exports = PacketAnalyzer;
