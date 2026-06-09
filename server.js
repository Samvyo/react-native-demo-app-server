const express = require("express");
const axios = require("axios");
const cors = require("cors");
const path = require("path");
const app = express();
const dotEnv = require("dotenv");
const https = require("https");
const fs = require("fs");
const jwt = require("jsonwebtoken");

dotEnv.config();
app.use(cors());
app.use(express.json());

const serverUrl = process.env.SERVER_URL;
const sdkBackendSecret = process.env.SDK_BACKEND_SECRET;
const meetingPlatformJwtSecret = process.env.MEETING_PLATFORM_JWT_SECRET;
const ACCESS_KEY = process.env.ACCESS_KEY;
const SECRET_ACCESS_KEY = process.env.SECRET_ACCESS_KEY;

app.post("/api/create-session-token", async (req, res) => {
  console.log("inside create-session-token");

  const { roomId, uuid, orgId } = req.body;
  if (!(ACCESS_KEY && SECRET_ACCESS_KEY)) {
    const authHeader = req.headers["authorization"] || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).send({
        success: false,
        message: "Missing Authorization token",
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, meetingPlatformJwtSecret);
    } catch (err) {
      console.error("Invalid meeting platform JWT:", err.message);
      return res.status(401).send({
        success: false,
        message: "Invalid or expired token",
      });
    }

    // In JWT mode, we still require roomId, uuid and orgId from the client.
    if (!roomId || !uuid || !orgId) {
      return res.status(400).send({
        success: false,
        message: "roomId, uuid and orgId are required",
      });
    }
  } else {
    // ACCESS_KEY / SECRET_ACCESS_KEY mode: only roomId is mandatory.
    if (!roomId) {
      return res.status(400).send({
        success: false,
        message: "roomId is required",
      });
    }
  }

  try {
    let response;
    // If ACCESS_KEY and SECRET_ACCESS_KEY are configured, use the default
    if (ACCESS_KEY && SECRET_ACCESS_KEY) {
      response = await axios.post(
        `${serverUrl}/api/siteSetting/sessionToken`,
        {
          roomId,
          accessKey: ACCESS_KEY,
          secretAccessKey: SECRET_ACCESS_KEY,
          orgIdParam: orgId,
        },
        {
          headers: {
            "x-sdk-backend-secret": sdkBackendSecret,
          },
        }
      );
    } else {
      // Fallback to existing behaviour using the sdkSessionToken route
      response = await axios.post(
        `${serverUrl}/api/siteSetting/sdkSessionToken`,
        {
          roomId,
          uuid,
          orgId,
        },
        {
          headers: {
            "x-sdk-backend-secret": sdkBackendSecret,
          },
        }
      );
    }

    if (response.data && response.data.success) {
      // Dashboard-mode support: resolve the samvyo room_setting _id ("rid") for
      // this roomId so the client can join as a dashboard-backed room (the
      // autoscaler marks roomStatus occupied only when a join carries rid).
      // Best-effort: an SDK-mode / ad-hoc roomId that isn't a configured
      // room_setting simply yields rid=null and the client joins as before.
      // fetchByQuery is uuid+room keyed (SELECT a.* → includes _id) and needs
      // no auth; uuid comes from the request or is derived from the org key.
      let rid = null;
      let roomDisplayName = null;
      try {
        const orgUuid =
          uuid || (ACCESS_KEY ? ACCESS_KEY.replace(/-\d+-\d+$/, "") : undefined);
        if (orgUuid) {
          const roomRes = await axios.post(
            `${serverUrl}/api/roomSetting/fetchByQuery`,
            { uuid: orgUuid, room: roomId },
            { timeout: 8000 }
          );
          const rs = roomRes.data && roomRes.data.roomSetting;
          const record = Array.isArray(rs) ? rs[0] : rs;
          if (record && record._id) {
            rid = record._id;
            // Carry the configured room name so the call logs + recordings show
            // the dashboard room's display name (autoscaler uses the client-sent
            // roomDisplayName for _displayName, not the fetched room_setting).
            roomDisplayName = record.name || null;
          }
        }
      } catch (ridErr) {
        console.log("rid resolution skipped:", ridErr.message);
      }

      return res.status(200).send({
        success: true,
        message: "Session token fetched successfully",
        sessionToken: response.data.sessionToken,
        rid,
        roomDisplayName,
      });
    }

    return res.status(400).send({
      success: false,
      message:
        response.data?.message || "Failed to fetch session token from server",
    });
  } catch (error) {
    console.error("Error creating session token:", error);
    console.log("Error message", error.message);
    const status = error.response?.status || 500;
    const message =
      error.response?.data?.message ||
      error.response?.data?.error ||
      "Internal Server Error";
    return res.status(status).json({ error: message, success: false });
  }
});

// app.get("/api/private-api-access-token", async (req, res) => {
//   console.log("inside private-api-access-token");
//   try {
//     const response = await axios.post(
//       `${serverUrl}/api/siteSetting/getAuthToken`,
//       {
//         accessKey,
//         secretAccessKey,
//       }
//     );

//     if (response.data.authToken.ok) {
//       return res.status(200).send({
//         success: true,
//         message: "Auth token fetched successfully",
//         token: response.data.authToken.token,
//       });
//     }

//     return res.status(400).send({
//       success: false,
//       message: "Failed to fetch auth token",
//     });
//   } catch (error) {
//     console.error("Error getting auth token:", error);
//     console.log("Error message:", error.message);
//     return res
//       .status(500)
//       .json({ error: "Internal Server Error", success: false });
//   }
// });

const port = process.env.PORT || 5100;

app.get("/", (req, res) => {
  res.send("Server is running on port " + port);
});

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// Item-7 LAN: serve HTTPS (the browser meeting app at :5174 is HTTPS, so an
// HTTP token endpoint would be blocked as mixed content). mkcert leaf cert.
const CERT_DIR = "/home/saurav/Work/samvyo/samvyo-app-autoscaler/.claude/tier-c-testing/certs";
https
  .createServer(
    {
      key: fs.readFileSync(path.join(CERT_DIR, "server.key")),
      cert: fs.readFileSync(path.join(CERT_DIR, "server.crt")),
    },
    app
  )
  .listen(port, "0.0.0.0", () => {
    console.log(`Secure (HTTPS) server running on port ${port}`);
  });
