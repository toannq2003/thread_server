const { SerialPort } = require("serialport");
const usbDetect = require("usb-detection");
const { savePacketData, updateKitStatus } = require("./database");

const connectedPorts = new Map();
const connectionAttempts = new Map();

async function listComPorts() {
  try {
    const ports = await SerialPort.list();
    return ports.map((p) => ({
      path: p.path,
      manufacturer: p.manufacturer || "Unknown",
      vendorId: p.vendorId || "Unknown",
      productId: p.productId || "Unknown",
    }));
  } catch (error) {
    console.error("Lỗi khi liệt kê cổng COM:", error);
    return [];
  }
}

async function updateComList(io) {
  try {
    const ports = Array.from(connectedPorts.values());
    console.log(
      "Gửi danh sách cổng COM hiện có:",
      ports.map((p) => p.path)
    );

    // Gửi danh sách COM port
    io.to("indexRoom").emit(
      "comList",
      ports.map((p, index) => ({
        id: index + 1,
        comPort: p.path,
        addrIpv6: "fe80::1",
      }))
    );

    // Gửi yêu cầu cập nhật danh sách kit
    io.to("indexRoom").emit("requestKitUpdate");
  } catch (error) {
    console.error("Lỗi khi gửi danh sách cổng COM hiện có:", error);
  }
}

async function connectToPort(path, io, clientComPorts) {
  if (connectedPorts.has(path)) {
    console.log(`Cổng ${path} đã được kết nối`);
    return;
  }

  const attempts = connectionAttempts.get(path) || 0;
  if (attempts >= 3) {
    connectionAttempts.delete(path);
    console.error(`Đã thử kết nối cổng ${path} quá nhiều lần, bỏ qua`);
    return;
  }

  try {
    console.log(`Đang thử kết nối đến cổng ${path}...`);
    const port = new SerialPort({
      path,
      baudRate: 115200,
      autoOpen: false,
    });

    port.open((err) => {
      if (err) {
        console.error(`Lỗi khi mở cổng ${path}:`, err.message);
        connectionAttempts.set(path, attempts + 1);
        if (attempts < 2) {
          setTimeout(() => {
            connectToPort(path, io, clientComPorts);
          }, 2000);
        }
        return;
      }

      console.log(`Cổng ${path} đã mở thành công`);
      connectedPorts.set(path, port);
      connectionAttempts.delete(path);
      updateComList(io);

      // State machine cho phân tích dữ liệu
      let state = "idle";
      let buffer = Buffer.alloc(0);
      let offset = 0;
      let type = 0,
        length = 0,
        totalLength = 0;

      port.on("data", async (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        while (buffer.length > offset) {
          switch (state) {
            case "idle":
              if (buffer.length - offset < 2) break;

              // Kiểm tra binary header: 0xAA 0x55
              if (buffer[offset] === 0xaa && buffer[offset + 1] === 0x55) {
                state = "binary";
                console.log(
                  `Phát hiện frame nhị phân: ${buffer
                    .subarray(offset, offset + 2)
                    .toString("hex")}`
                );
                continue;
              }
              // Kiểm tra string patterns
              else if (
                (buffer[offset] === 0x0d && buffer[offset + 1] === 0x0a) ||
                (buffer[offset] === 0x3e && buffer[offset + 1] === 0x20)
              ) {
                state = "string";
                continue;
              } else {
                offset++;
                continue;
              }

            case "string":
              const stringData = buffer.subarray(0, offset + 2).toString();
              console.log("String data:", stringData);

              // Gửi CLI response về web
              io.to("indexRoom").emit("cliResponse", {
                success: 1,
                comPort: path,
                response: stringData,
              });

              buffer = buffer.subarray(offset + 2);
              offset = 0;
              state = "idle";
              continue;

            case "binary":
              if (buffer.length - offset < 4) break;

              type = buffer[offset + 2];
              length = buffer[offset + 3];

              console.log(`Type: 0x${type.toString(16)}, Length: ${length}`);

              switch (type) {
                case 0xfd: // TX frame
                  state = "binary_tx";
                  totalLength = 2 + 1 + 1 + length + 8 + 1 + 1 + 1 + 4 + 2;
                  console.log(`Binary TX frame length: ${totalLength}`);
                  break;

                case 0xf9: // RX frame
                  state = "binary_rx";
                  totalLength =
                    2 + 1 + 1 + length + 8 + 1 + 1 + 1 + 4 + 1 + 1 + 1 + 2;
                  console.log(`Binary RX frame length: ${totalLength}`);
                  break;

                default:
                  console.warn("Unknown binary type:", type.toString(16));
                  state = "idle";
                  offset++;
                  continue;
              }
              continue;

            case "binary_tx":
            case "binary_rx":
              console.log(
                `Buffer available: ${
                  buffer.length - offset
                }, Required: ${totalLength}`
              );

              if (buffer.length - offset < totalLength) break;

              // Kiểm tra footer: 0x0D 0x0A
              if (
                buffer[offset + totalLength - 2] === 0x0d &&
                buffer[offset + totalLength - 1] === 0x0a
              ) {
                console.log(`Xử lý frame ${state} với độ dài ${totalLength}`);

                // Trích xuất dữ liệu từ frame
                const frameData = buffer.subarray(offset, offset + totalLength);

                let packetLength = frameData[3];
                let packetData = frameData
                  .subarray(4, 4 + packetLength)
                  .toString("hex");
                let kitUnique = frameData
                  .subarray(4 + packetLength, 4 + packetLength + 8)
                  .toString("hex");
                let errorCode = frameData[4 + packetLength + 8];
                let isAck = frameData[4 + packetLength + 9] === 1;
                let channel = frameData[4 + packetLength + 10];
                let kitTimestamp = frameData.readUInt32LE(
                  4 + packetLength + 11
                );

                let packetInfo = {
                  type: state === "binary_tx" ? "TX" : "RX",
                  packetLength,
                  packetData,
                  kitUnique,
                  errorCode,
                  isAck,
                  channel,
                  comPort: path,
                  kitTimestamp: kitTimestamp,
                };

                // Thêm thông tin RX nếu là frame RX
                if (state === "binary_rx") {
                    
                  let crcPassed = frameData[4 + packetLength + 15] === 1;
                  let rssi = frameData[4 + packetLength + 16];
                  let lqi = frameData[4 + packetLength + 17];

                  packetInfo.crcPassed = crcPassed;
                  packetInfo.rssi = rssi;
                  packetInfo.lqi = lqi;
                  console.log(`crc: ${packetInfo.crcPassed}`);
                }

                // Để lại phần còn lại
                const first = buffer.subarray(0, offset);
                const second = buffer.subarray(offset + totalLength);
                buffer = Buffer.concat([first, second]);
                state = "idle";


                try {

                  //Gửi dữ liệu real-time cho client
                  io.to("indexRoom").emit("newPacketData", {
                    ...packetInfo,
                    timestamp: new Date(),
                  });

                  let kitUpdate = {

                  }

                  // Gửi cập nhật kit
                  io.to("indexRoom").emit("requestKitUpdate");

                  // Lưu vào database
                  await savePacketData(packetInfo);

                  console.log(
                    `Đã lưu packet ${packetInfo.type} từ kit ${packetInfo.kitUnique}`
                  );
                } catch (error) {
                  console.error(
                    `Lỗi khi lưu dữ liệu ${packetInfo.type}:`,
                    error
                  );
                }

                continue;
              } else {
                console.warn("Lỗi đồng bộ, không tìm thấy footer hợp lệ");
                console.warn(
                  "Footer nhận được:",
                  buffer
                    .subarray(offset + totalLength - 2, offset + totalLength)
                    .toString("hex")
                );
                offset++;
                state = "idle";
                continue;
              }

            default:
              console.error("Unknown state:", state);
              offset++;
              state = "idle";
              continue;
          }
          break;
        }
      });

      port.on("error", async (err) => {
        console.error(`Lỗi cổng ${path}:`, err.message);
        connectedPorts.delete(path);
        await updateKitStatus(path, "offline");
        updateComList(io);
      });

      port.on("close", async () => {
        console.log(`Cổng ${path} đã đóng`);
        connectedPorts.delete(path);
        await updateKitStatus(path, "offline");
        updateComList(io);
      });
    });
  } catch (error) {
    console.error(`Lỗi khi khởi tạo cổng ${path}:`, error.message);
    connectionAttempts.set(path, attempts + 1);
  }
}

function monitorPorts(io, clientComPorts) {
  initializeExistingPorts(io, clientComPorts);

  usbDetect.startMonitoring();
  usbDetect.on("add", async () => {
    console.log("Phát hiện thiết bị USB mới");
    setTimeout(async () => {
      const ports = await listComPorts();
      console.log(
        "Danh sách cổng sau khi thêm USB:",
        ports.map((p) => p.path)
      );
      for (const p of ports) {
        await connectToPort(p.path, io, clientComPorts);
      }
    }, 1000);
  });
}

async function initializeExistingPorts(io, clientComPorts) {
  console.log("Khởi tạo kết nối đến các cổng hiện có...");
  const ports = await listComPorts();
  for (const p of ports) {
    await connectToPort(p.path, io, clientComPorts);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

function sendCliCommand(comPort, command) {
  const port = connectedPorts.get(comPort);
  if (port && port.isOpen) {
    port.write(`${command}\r\n`, (err) => {
      if (err) {
        return console.log("Error on write:", err.message);
      }
    });
    console.log("Đã gửi lệnh:", command, "đến cổng", comPort);
    return true;
  }
  return false;
}

// Thêm vào cuối file serial.js
function getConnectedPorts() {
  return connectedPorts;
}

// Cập nhật module.exports
module.exports = {
  monitorPorts,
  sendCliCommand,
  listComPorts,
  getConnectedPorts, // Thêm function mới
};
