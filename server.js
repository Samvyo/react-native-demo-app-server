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
          uuid,
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
      return res.status(200).send({
        success: true,
        message: "Session token fetched successfully",
        sessionToken: response.data.sessionToken,
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

app.listen(port, () => {
  console.log(`Secure server running on port ${port}`);
});
